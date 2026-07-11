// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use registry_notary_core::{
    AccessMode, BatchEvaluateItemRequest, BatchEvaluateRequest, BatchOperationConfig, BulkMode,
    ClaimDefinition, ClaimOperationsConfig, ClaimRef, ClaimValueConfig, DciSourceConnectionConfig,
    DisclosureConfig, EcosystemBindingSelectorConfig, EvaluateRequest, EvidenceAssurance,
    EvidenceAuthorizationDetails, EvidenceConfig, EvidenceEcosystemBindingConfig, EvidenceEntity,
    EvidenceError, EvidenceIdentifier, EvidencePrincipal, EvidenceRelationship,
    EvidenceRequestContext, OperationConfig, RuleConfig, SourceBindingConfig,
    SourceConnectionConfig, SourceConnectorKind, SourceFieldConfig, SourceLookupConfig,
    SourceMatchingConfig, SourceQueryFieldConfig, SubjectRequest, FORMAT_CLAIM_RESULT_JSON,
};
use registry_notary_server::{
    BatchEvaluateOptions, EvidenceStore, RegistryNotaryRuntime, SourceReader,
};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const TEST_SERVICE_ID: &str = "registry-notary";

#[derive(Debug)]
struct MatchingSource {
    reads: AtomicUsize,
}

impl MatchingSource {
    fn new() -> Self {
        Self {
            reads: AtomicUsize::new(0),
        }
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl SourceReader for MatchingSource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async { Err(EvidenceError::TargetAttributesInsufficient) })
    }

    fn read_one_for_context<'a>(
        &'a self,
        binding: &'a SourceBindingConfig,
        context: &'a EvidenceRequestContext,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::SeqCst);
            match binding.entity.as_str() {
                "person" => match_person(context),
                "land_parcel" => match_land_parcel(context),
                _ => Err(EvidenceError::SourceUnavailable),
            }
        })
    }

    fn required_scopes(
        &self,
        _evidence: &EvidenceConfig,
        _claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        Ok(Vec::new())
    }
}

#[derive(Debug)]
struct ObservedAtSource {
    preflight_observed_at: Option<String>,
    row_observed_at: Option<String>,
    reads: AtomicUsize,
}

impl ObservedAtSource {
    fn new(observed_at: Option<String>) -> Self {
        Self {
            preflight_observed_at: observed_at.clone(),
            row_observed_at: observed_at,
            reads: AtomicUsize::new(0),
        }
    }

    fn with_preflight_and_row(
        preflight_observed_at: Option<String>,
        row_observed_at: Option<String>,
    ) -> Self {
        Self {
            preflight_observed_at,
            row_observed_at,
            reads: AtomicUsize::new(0),
        }
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl SourceReader for ObservedAtSource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async { Err(EvidenceError::TargetAttributesInsufficient) })
    }

    fn read_one_for_context<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _context: &'a EvidenceRequestContext,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let mut row = json!({"alive": true});
            if let Some(observed_at) = self.row_observed_at.as_deref() {
                row["observed_at"] = json!(observed_at);
            }
            Ok(row)
        })
    }

    fn source_observed_at_for_context<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _context: &'a EvidenceRequestContext,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<OffsetDateTime>, EvidenceError>> + Send + 'a>>
    {
        Box::pin(async move {
            let Some(observed_at) = self.preflight_observed_at.as_deref() else {
                return Ok(None);
            };
            OffsetDateTime::parse(observed_at, &Rfc3339)
                .map(Some)
                .map_err(|_| EvidenceError::TargetMatchingPolicyRejected)
        })
    }

    fn required_scopes(
        &self,
        _evidence: &EvidenceConfig,
        _claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        Ok(Vec::new())
    }
}

#[derive(Debug)]
struct ObjectProfileSource {
    reads: AtomicUsize,
}

impl ObjectProfileSource {
    fn new() -> Self {
        Self {
            reads: AtomicUsize::new(0),
        }
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl SourceReader for ObjectProfileSource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async { Err(EvidenceError::TargetAttributesInsufficient) })
    }

    fn read_one_for_context<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _context: &'a EvidenceRequestContext,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(json!({
                "profile": {
                    "given_name": "Amina",
                    "family_name": "Diallo",
                    "birthdate": "1984-02-10"
                }
            }))
        })
    }

    fn required_scopes(
        &self,
        _evidence: &EvidenceConfig,
        _claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        Ok(Vec::new())
    }
}

#[derive(Debug)]
struct ContextRecordingSource {
    seen: Mutex<Option<EvidenceRequestContext>>,
}

impl ContextRecordingSource {
    fn new() -> Self {
        Self {
            seen: Mutex::new(None),
        }
    }

    fn seen(&self) -> EvidenceRequestContext {
        self.seen
            .lock()
            .expect("seen context mutex is not poisoned")
            .clone()
            .expect("source received a context")
    }
}

#[derive(Debug)]
struct BatchContextRecordingSource {
    seen_batches: Mutex<Vec<Vec<EvidenceRequestContext>>>,
    read_many_calls: AtomicUsize,
    read_one_calls: AtomicUsize,
}

impl BatchContextRecordingSource {
    fn new() -> Self {
        Self {
            seen_batches: Mutex::new(Vec::new()),
            read_many_calls: AtomicUsize::new(0),
            read_one_calls: AtomicUsize::new(0),
        }
    }

    fn seen_batches(&self) -> Vec<Vec<EvidenceRequestContext>> {
        self.seen_batches
            .lock()
            .expect("seen batches mutex is not poisoned")
            .clone()
    }

    fn read_many_calls(&self) -> usize {
        self.read_many_calls.load(Ordering::SeqCst)
    }

    fn read_one_calls(&self) -> usize {
        self.read_one_calls.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
struct DelayedContextSource;

#[derive(Debug)]
struct DelayedMultiPolicySource;

impl SourceReader for DelayedContextSource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async { Err(EvidenceError::TargetAttributesInsufficient) })
    }

    fn read_one_for_context<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        context: &'a EvidenceRequestContext,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let id = context
                .target
                .id
                .as_deref()
                .ok_or(EvidenceError::TargetAttributesInsufficient)?;
            Ok(json!({ "id": id }))
        })
    }

    fn required_scopes(
        &self,
        _evidence: &EvidenceConfig,
        _claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        Ok(Vec::new())
    }
}

impl SourceReader for DelayedMultiPolicySource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async { Err(EvidenceError::TargetAttributesInsufficient) })
    }

    fn read_one_for_context<'a>(
        &'a self,
        binding: &'a SourceBindingConfig,
        _context: &'a EvidenceRequestContext,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            if binding.entity == "person_alpha" {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(json!({ "alive": true }))
        })
    }

    fn required_scopes(
        &self,
        _evidence: &EvidenceConfig,
        _claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        Ok(Vec::new())
    }
}

impl SourceReader for ContextRecordingSource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async { Err(EvidenceError::TargetAttributesInsufficient) })
    }

    fn read_one_for_context<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        context: &'a EvidenceRequestContext,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            *self
                .seen
                .lock()
                .expect("seen context mutex is not poisoned") = Some(context.clone());
            Ok(json!({ "alive": true }))
        })
    }

    fn required_scopes(
        &self,
        _evidence: &EvidenceConfig,
        _claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        Ok(Vec::new())
    }
}

impl SourceReader for BatchContextRecordingSource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async {
            self.read_one_calls.fetch_add(1, Ordering::SeqCst);
            Err(EvidenceError::SourceUnavailable)
        })
    }

    fn read_one_for_context<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _context: &'a EvidenceRequestContext,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async {
            self.read_one_calls.fetch_add(1, Ordering::SeqCst);
            Err(EvidenceError::SourceUnavailable)
        })
    }

    fn read_many_context<'a>(
        &'a self,
        bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)>,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
        Box::pin(async move {
            self.read_many_calls.fetch_add(1, Ordering::SeqCst);
            let contexts: Vec<EvidenceRequestContext> = bindings
                .iter()
                .map(|(_, context)| context.clone())
                .collect();
            self.seen_batches
                .lock()
                .expect("seen batches mutex is not poisoned")
                .push(contexts);
            bindings
                .iter()
                .map(|_| Ok(json!({ "alive": true })))
                .collect()
        })
    }

    fn required_scopes(
        &self,
        _evidence: &EvidenceConfig,
        _claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        Ok(Vec::new())
    }
}

#[derive(Debug)]
struct RequesterSensitiveBatchSource {
    read_many_calls: AtomicUsize,
    read_one_calls: AtomicUsize,
    seen_batches: Mutex<Vec<Vec<EvidenceRequestContext>>>,
}

impl RequesterSensitiveBatchSource {
    fn new() -> Self {
        Self {
            read_many_calls: AtomicUsize::new(0),
            read_one_calls: AtomicUsize::new(0),
            seen_batches: Mutex::new(Vec::new()),
        }
    }

    fn read_many_calls(&self) -> usize {
        self.read_many_calls.load(Ordering::SeqCst)
    }

    fn read_one_calls(&self) -> usize {
        self.read_one_calls.load(Ordering::SeqCst)
    }

    fn seen_batches(&self) -> Vec<Vec<EvidenceRequestContext>> {
        self.seen_batches
            .lock()
            .expect("seen batches mutex is not poisoned")
            .clone()
    }
}

impl SourceReader for RequesterSensitiveBatchSource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async {
            self.read_one_calls.fetch_add(1, Ordering::SeqCst);
            Err(EvidenceError::SourceUnavailable)
        })
    }

    fn read_one_for_context<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        context: &'a EvidenceRequestContext,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            self.read_one_calls.fetch_add(1, Ordering::SeqCst);
            requester_office_alive(context)
        })
    }

    fn read_many_context<'a>(
        &'a self,
        bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)>,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
        Box::pin(async move {
            self.read_many_calls.fetch_add(1, Ordering::SeqCst);
            let contexts: Vec<EvidenceRequestContext> = bindings
                .iter()
                .map(|(_, context)| context.clone())
                .collect();
            self.seen_batches
                .lock()
                .expect("seen batches mutex is not poisoned")
                .push(contexts);
            bindings
                .iter()
                .map(|(_, context)| requester_office_alive(context))
                .collect()
        })
    }

    fn required_scopes(
        &self,
        _evidence: &EvidenceConfig,
        _claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        Ok(Vec::new())
    }
}

fn requester_office_alive(context: &EvidenceRequestContext) -> Result<Value, EvidenceError> {
    let office = context
        .requester
        .as_ref()
        .and_then(|requester| requester.attributes.get("office"))
        .and_then(Value::as_str)
        .ok_or(EvidenceError::RequesterMatchingPolicyRejected)?;
    Ok(json!({ "alive": office == "north" }))
}

fn match_person(context: &EvidenceRequestContext) -> Result<Value, EvidenceError> {
    let given_name = target_attr(context, "given_name")?;
    let family_name = target_attr(context, "family_name")?;
    let birthdate = target_attr(context, "birthdate")?;
    if given_name == json!("Inactive") {
        return Err(EvidenceError::TargetNotInValidState);
    }
    if given_name == json!("Low") {
        return Err(EvidenceError::TargetMatchLowConfidence);
    }
    let rows = [
        json!({"entity_id": "p-1", "given_name": "Amina", "family_name": "Diallo", "birthdate": "1984-02-10", "alive": true}),
        json!({"entity_id": "p-duplicate", "given_name": "Amina", "family_name": "Diallo", "birthdate": "1980-01-01", "alive": true}),
        json!({"entity_id": "p-duplicate", "given_name": "Amina", "family_name": "Diallo", "birthdate": "1980-01-01", "alive": true}),
        json!({"entity_id": "p-2", "given_name": "Amina", "family_name": "Diallo", "birthdate": "1975-05-05", "alive": true}),
        json!({"entity_id": "p-3", "given_name": "Amina", "family_name": "Diallo", "birthdate": "1975-05-05", "alive": true}),
    ];
    let matches: Vec<&Value> = rows
        .iter()
        .filter(|row| {
            row["given_name"] == given_name
                && row["family_name"] == family_name
                && row["birthdate"] == birthdate
        })
        .collect();
    distinct_entity_match(matches)
}

fn match_land_parcel(context: &EvidenceRequestContext) -> Result<Value, EvidenceError> {
    let Some(parcel_id) = context.target.identifier_value("cadastral_reference") else {
        return Err(EvidenceError::TargetAttributesInsufficient);
    };
    match parcel_id {
        "PARCEL-8891" => Ok(json!({
            "parcel_id": "PARCEL-8891",
            "registered": true,
            "area_ha": 2.4
        })),
        _ => Err(EvidenceError::SourceNotFound),
    }
}

fn distinct_entity_match(matches: Vec<&Value>) -> Result<Value, EvidenceError> {
    let ids: BTreeSet<String> = matches
        .iter()
        .filter_map(|row| row["entity_id"].as_str().map(str::to_string))
        .collect();
    match ids.len() {
        0 => Err(EvidenceError::SourceNotFound),
        1 => matches
            .first()
            .cloned()
            .cloned()
            .ok_or(EvidenceError::SourceUnavailable),
        _ => Err(EvidenceError::SourceAmbiguous),
    }
}

fn target_attr(context: &EvidenceRequestContext, key: &str) -> Result<Value, EvidenceError> {
    context
        .target
        .attributes
        .get(key)
        .cloned()
        .ok_or(EvidenceError::TargetAttributesInsufficient)
}

fn person_target(given_name: &str, family_name: &str, birthdate: Option<&str>) -> EvidenceEntity {
    let mut target = EvidenceEntity::new("Person");
    target
        .attributes
        .insert("given_name".to_string(), json!(given_name));
    target
        .attributes
        .insert("family_name".to_string(), json!(family_name));
    if let Some(birthdate) = birthdate {
        target
            .attributes
            .insert("birthdate".to_string(), json!(birthdate));
    }
    target
}

fn land_target(parcel_id: &str) -> EvidenceEntity {
    EvidenceEntity::with_identifier("LandParcel", "cadastral_reference", parcel_id)
}

fn evidence_config(claims: Vec<ClaimDefinition>) -> Arc<EvidenceConfig> {
    Arc::new(EvidenceConfig {
        enabled: true,
        service_id: TEST_SERVICE_ID.to_string(),
        inline_batch_limit: 20,
        claims,
        ..EvidenceConfig::default()
    })
}

fn evidence_config_with_source_adapter_batch_connection(
    claims: Vec<ClaimDefinition>,
) -> Arc<EvidenceConfig> {
    Arc::new(EvidenceConfig {
        enabled: true,
        service_id: TEST_SERVICE_ID.to_string(),
        inline_batch_limit: 20,
        source_connections: BTreeMap::from([(
            "source_adapter_crvs".to_string(),
            SourceConnectionConfig {
                base_url: "http://127.0.0.1:9191".to_string(),
                allow_insecure_localhost: true,
                allow_insecure_private_network: false,
                token_env: "SOURCE_ADAPTER_SIDECAR_TOKEN".to_string(),
                source_auth: None,
                expected_sidecar: None,
                dci: DciSourceConnectionConfig::default(),
                max_in_flight: 8,
                retry_on_5xx: false,
                bulk_mode: BulkMode::SourceAdapterSidecarBatch,
                bulk_mode_lookup_unique: false,
                bulk_timeout_max_ms: 30_000,
            },
        )]),
        claims,
        ..EvidenceConfig::default()
    })
}

fn evidence_config_with_allowed_purposes(
    claims: Vec<ClaimDefinition>,
    allowed_purposes: Vec<String>,
) -> Arc<EvidenceConfig> {
    Arc::new(EvidenceConfig {
        enabled: true,
        service_id: TEST_SERVICE_ID.to_string(),
        inline_batch_limit: 20,
        allowed_purposes,
        claims,
        ..EvidenceConfig::default()
    })
}

fn person_claim() -> ClaimDefinition {
    claim(
        "person-is-alive",
        "person",
        "alive",
        "Person",
        SourceMatchingConfig {
            policy_id: Some("demo-person-name-birthdate-v1".to_string()),
            method: Some("exact_name_birthdate".to_string()),
            target_type: Some("Person".to_string()),
            allowed_purposes: vec!["benefits".to_string()],
            allowed_relationships: vec!["self".to_string()],
            sufficient_target_inputs: vec![vec![
                "target.attributes.given_name".to_string(),
                "target.attributes.family_name".to_string(),
                "target.attributes.birthdate".to_string(),
            ]],
            allowed_target_inputs: vec!["target.attributes.*".to_string()],
            collapse_matching_errors: false,
            confidence: Some("high".to_string()),
            ..SourceMatchingConfig::default()
        },
    )
}

fn freshness_gated_person_claim() -> ClaimDefinition {
    claim(
        "fresh-person-is-alive",
        "person",
        "alive",
        "Person",
        SourceMatchingConfig {
            policy_id: Some("demo-person-freshness-v1".to_string()),
            target_type: Some("Person".to_string()),
            allowed_purposes: vec!["benefits".to_string()],
            max_source_age_seconds: Some(60),
            source_observed_at_field: Some("observed_at".to_string()),
            collapse_matching_errors: false,
            ..SourceMatchingConfig::default()
        },
    )
}

fn parcel_claim() -> ClaimDefinition {
    claim(
        "land-parcel-is-registered",
        "land_parcel",
        "registered",
        "LandParcel",
        SourceMatchingConfig {
            policy_id: Some("demo-land-parcel-cadastral-v1".to_string()),
            method: Some("exact_cadastral_reference".to_string()),
            target_type: Some("LandParcel".to_string()),
            allowed_purposes: vec!["benefits".to_string()],
            sufficient_target_inputs: vec![vec![
                "target.identifiers.cadastral_reference".to_string()
            ]],
            allowed_target_inputs: vec!["target.identifiers.cadastral_reference".to_string()],
            collapse_matching_errors: false,
            confidence: Some("high".to_string()),
            ..SourceMatchingConfig::default()
        },
    )
}

fn person_profile_claim() -> ClaimDefinition {
    let mut claim = claim(
        "person-profile",
        "person_profile",
        "profile",
        "Person",
        SourceMatchingConfig {
            policy_id: Some("demo-person-profile-v1".to_string()),
            method: Some("exact_name_birthdate".to_string()),
            target_type: Some("Person".to_string()),
            allowed_purposes: vec!["benefits".to_string()],
            allowed_relationships: vec!["self".to_string()],
            sufficient_target_inputs: vec![vec![
                "target.attributes.given_name".to_string(),
                "target.attributes.family_name".to_string(),
                "target.attributes.birthdate".to_string(),
            ]],
            allowed_target_inputs: vec!["target.attributes.*".to_string()],
            collapse_matching_errors: false,
            confidence: Some("high".to_string()),
            ..SourceMatchingConfig::default()
        },
    );
    claim.value.value_type = "object".to_string();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .fields
        .get_mut("profile")
        .expect("profile source field exists")
        .field_type = Some("object".to_string());
    claim.disclosure.allowed = vec!["value".to_string()];
    claim
}

fn claim(
    id: &str,
    entity: &str,
    field: &str,
    target_type: &str,
    matching: SourceMatchingConfig,
) -> ClaimDefinition {
    ClaimDefinition {
        id: id.to_string(),
        title: id.to_string(),
        version: "1.0.0".to_string(),
        subject_type: target_type.to_string(),
        value: ClaimValueConfig {
            value_type: "boolean".to_string(),
            unit: None,
        },
        semantics: None,
        inputs: Vec::new(),
        depends_on: Vec::new(),
        purpose: None,
        source_bindings: BTreeMap::from([(
            "src".to_string(),
            SourceBindingConfig {
                connector: SourceConnectorKind::RegistryDataApi,
                connection: None,
                required_scope: None,
                dataset: "demo".to_string(),
                entity: entity.to_string(),
                lookup: SourceLookupConfig {
                    input: "target.id".to_string(),
                    field: "id".to_string(),
                    op: "eq".to_string(),
                    cardinality: "one".to_string(),
                },
                query_fields: Vec::new(),
                fields: BTreeMap::from([(
                    field.to_string(),
                    SourceFieldConfig {
                        field: field.to_string(),
                        field_type: Some("boolean".to_string()),
                        unit: None,
                        required: true,
                        semantic_term: None,
                    },
                )]),
                matching,
            },
        )]),
        rule: RuleConfig::Extract {
            source: "src".to_string(),
            field: field.to_string(),
        },
        operations: ClaimOperationsConfig {
            evaluate: OperationConfig { enabled: true },
            batch_evaluate: BatchOperationConfig {
                enabled: true,
                max_subjects: 20,
            },
        },
        disclosure: DisclosureConfig {
            default: "value".to_string(),
            allowed: vec!["value".to_string(), "predicate".to_string()],
            downgrade: "predicate".to_string(),
        },
        formats: vec![FORMAT_CLAIM_RESULT_JSON.to_string()],
        credential_profiles: Vec::new(),
        cccev: None,
        oots: None,
    }
}

fn principal() -> EvidencePrincipal {
    EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
        principal_id: "client".to_string(),
        scopes: Vec::new(),
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    }
}

fn matching_policy_rule_ids(entity: &str, suffixes: &[&str]) -> Vec<String> {
    suffixes
        .iter()
        .map(|suffix| format!("source-binding-policy:{entity}.{suffix}"))
        .collect()
}

fn principal_with_policy_context(
    assurance_level: Option<&str>,
    jurisdiction: Option<&str>,
    legal_basis_ref: Option<&str>,
    consent_ref: Option<&str>,
) -> EvidencePrincipal {
    let mut principal = principal();
    principal.authorization_details = Some(EvidenceAuthorizationDetails {
        detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE.to_string(),
        schema_version: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
            .to_string(),
        actions: vec!["evaluate".to_string()],
        locations: vec![TEST_SERVICE_ID.to_string()],
        claims: vec![ClaimRef::with_version("person-is-alive", "1.0.0")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("benefits".to_string()),
        legal_basis_ref: legal_basis_ref.map(ToOwned::to_owned),
        consent_ref: consent_ref.map(ToOwned::to_owned),
        jurisdiction: jurisdiction.map(ToOwned::to_owned),
        assurance_level: assurance_level.map(ToOwned::to_owned),
        subject: None,
        target: None,
        relationship: None,
        access_mode: Some(AccessMode::MachineClient),
        assisted_access_context: None,
    });
    principal
}

fn principal_with_context_only_policy_context(
    assurance_level: Option<&str>,
    jurisdiction: Option<&str>,
    legal_basis_ref: Option<&str>,
    consent_ref: Option<&str>,
) -> EvidencePrincipal {
    let mut principal = principal();
    principal.authorization_details = Some(EvidenceAuthorizationDetails {
        detail_type: "registry-notary/evidence-authorization/v1".to_string(),
        schema_version: "v1".to_string(),
        legal_basis_ref: legal_basis_ref.map(ToOwned::to_owned),
        consent_ref: consent_ref.map(ToOwned::to_owned),
        jurisdiction: jurisdiction.map(ToOwned::to_owned),
        assurance_level: assurance_level.map(ToOwned::to_owned),
        ..EvidenceAuthorizationDetails::default()
    });
    principal
}

fn evaluate_request(target: EvidenceEntity, claim: &str) -> EvaluateRequest {
    EvaluateRequest {
        requester: None,
        target: Some(target),
        relationship: Some(EvidenceRelationship {
            relationship_type: "self".to_string(),
            attributes: BTreeMap::new(),
        }),
        on_behalf_of: None,
        claims: vec![ClaimRef::new(claim)],
        disclosure: Some("value".to_string()),
        format: None,
        purpose: Some("benefits".to_string()),
    }
}

fn observed_person_target() -> EvidenceEntity {
    let mut target = EvidenceEntity::new("Person");
    target.id = Some("p-1".to_string());
    target
}

fn requester_with_office(office: &str) -> EvidenceEntity {
    let mut requester = EvidenceEntity::new("Person");
    requester
        .attributes
        .insert("office".to_string(), json!(office));
    requester
}

#[tokio::test]
async fn person_name_birthdate_unique_match_succeeds_with_metadata() {
    let runtime = RegistryNotaryRuntime::new();
    let store = EvidenceStore::default();
    let source = Arc::new(MatchingSource::new());
    let results = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &store,
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect("unique person match succeeds");

    assert_eq!(results[0].value, Some(json!(true)));
    assert_eq!(results[0].target_ref.entity_type, "Person");
    assert_eq!(
        results[0]
            .matching
            .as_ref()
            .map(|metadata| metadata.policy_id.as_str()),
        Some("demo-person-name-birthdate-v1")
    );
    let matching = results[0]
        .matching
        .as_ref()
        .expect("successful configured match carries metadata");
    assert_eq!(matching.method, "exact_name_birthdate");
    assert_eq!(matching.confidence, "high");
    assert_eq!(matching.score, None);
    assert_eq!(source.reads(), 1);
}

#[tokio::test]
async fn source_observed_at_contract_enforces_matching_freshness() {
    let runtime = RegistryNotaryRuntime::new();
    let store = EvidenceStore::default();
    let fresh_observed_at = (OffsetDateTime::now_utc() - time::Duration::seconds(10))
        .format(&Rfc3339)
        .expect("fresh observed timestamp formats");
    let fresh_source = Arc::new(ObservedAtSource::new(Some(fresh_observed_at)));
    let fresh = runtime
        .evaluate(
            evidence_config(vec![freshness_gated_person_claim()]),
            fresh_source.clone(),
            &store,
            &principal(),
            evaluate_request(observed_person_target(), "fresh-person-is-alive"),
            None,
        )
        .await
        .expect("fresh source observation satisfies max age");

    assert_eq!(fresh[0].value, Some(json!(true)));
    assert_eq!(fresh_source.reads(), 1);

    let stale_observed_at = (OffsetDateTime::now_utc() - time::Duration::seconds(61))
        .format(&Rfc3339)
        .expect("stale observed timestamp formats");
    let stale_source = Arc::new(ObservedAtSource::new(Some(stale_observed_at)));
    let stale = runtime
        .evaluate(
            evidence_config(vec![freshness_gated_person_claim()]),
            stale_source.clone(),
            &store,
            &principal(),
            evaluate_request(observed_person_target(), "fresh-person-is-alive"),
            None,
        )
        .await
        .expect_err("stale source observation is rejected");

    assert_eq!(stale.code(), "pdp.evidence_stale");
    assert_eq!(
        stale_source.reads(),
        0,
        "stale freshness must deny before reading the protected source row"
    );

    let missing_source = Arc::new(ObservedAtSource::new(None));
    let missing = runtime
        .evaluate(
            evidence_config(vec![freshness_gated_person_claim()]),
            missing_source.clone(),
            &store,
            &principal(),
            evaluate_request(observed_person_target(), "fresh-person-is-alive"),
            None,
        )
        .await
        .expect_err("missing source observation is rejected");

    assert_eq!(missing.code(), "pdp.evidence_stale");
    assert_eq!(
        missing_source.reads(),
        0,
        "missing freshness must deny before reading the protected source row"
    );
}

#[tokio::test]
async fn direct_freshness_rechecks_row_timestamp_after_fresh_preflight() {
    let runtime = RegistryNotaryRuntime::new();
    let store = EvidenceStore::default();
    let fresh_preflight = (OffsetDateTime::now_utc() - time::Duration::seconds(10))
        .format(&Rfc3339)
        .expect("fresh preflight timestamp formats");
    let stale_row = (OffsetDateTime::now_utc() - time::Duration::seconds(61))
        .format(&Rfc3339)
        .expect("stale row timestamp formats");
    let stale_source = Arc::new(ObservedAtSource::with_preflight_and_row(
        Some(fresh_preflight.clone()),
        Some(stale_row),
    ));

    let stale = runtime
        .evaluate(
            evidence_config(vec![freshness_gated_person_claim()]),
            stale_source.clone(),
            &store,
            &principal(),
            evaluate_request(observed_person_target(), "fresh-person-is-alive"),
            None,
        )
        .await
        .expect_err("stale row observation is rejected even after fresh preflight");

    assert_eq!(stale.code(), "pdp.evidence_stale");
    assert_eq!(
        stale_source.reads(),
        1,
        "fresh preflight allows one protected row read, but stale row freshness denies before disclosure"
    );

    let missing_source = Arc::new(ObservedAtSource::with_preflight_and_row(
        Some(fresh_preflight),
        None,
    ));
    let missing = runtime
        .evaluate(
            evidence_config(vec![freshness_gated_person_claim()]),
            missing_source.clone(),
            &store,
            &principal(),
            evaluate_request(observed_person_target(), "fresh-person-is-alive"),
            None,
        )
        .await
        .expect_err("missing row observation is rejected even after fresh preflight");

    assert_eq!(missing.code(), "pdp.evidence_stale");
    assert_eq!(
        missing_source.reads(),
        1,
        "fresh preflight allows one protected row read, but missing row freshness denies before disclosure"
    );
}

#[tokio::test]
async fn multi_source_matching_metadata_uses_one_deterministic_policy_identity() {
    let runtime = RegistryNotaryRuntime::new();
    let store = EvidenceStore::default();
    let source = Arc::new(DelayedMultiPolicySource);
    let mut claim = claim(
        "multi-policy-person-is-alive",
        "person_alpha",
        "alive",
        "Person",
        SourceMatchingConfig {
            method: Some("configured_lookup".to_string()),
            confidence: Some("high".to_string()),
            allowed_purposes: vec!["benefits".to_string()],
            ecosystem_binding: Some(EcosystemBindingSelectorConfig {
                id: Some("alpha-pack".to_string()),
                ..EcosystemBindingSelectorConfig::default()
            }),
            ..SourceMatchingConfig::default()
        },
    );
    let alpha = claim
        .source_bindings
        .remove("src")
        .expect("source binding exists");
    let mut zeta = alpha.clone();
    zeta.entity = "person_zeta".to_string();
    zeta.matching.ecosystem_binding = Some(EcosystemBindingSelectorConfig {
        id: Some("zeta-pack".to_string()),
        ..EcosystemBindingSelectorConfig::default()
    });
    claim.source_bindings =
        BTreeMap::from([("alpha".to_string(), alpha), ("zeta".to_string(), zeta)]);
    claim.rule = RuleConfig::Extract {
        source: "alpha".to_string(),
        field: "alive".to_string(),
    };
    let evidence = Arc::new(EvidenceConfig {
        enabled: true,
        inline_batch_limit: 20,
        ecosystem_bindings: BTreeMap::from([
            (
                "alpha-pack".to_string(),
                EvidenceEcosystemBindingConfig {
                    profile: Some("odrl:v1".to_string()),
                    policy_id: "alpha-policy".to_string(),
                    policy_hash:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    unsupported_odrl_terms: Vec::new(),
                },
            ),
            (
                "zeta-pack".to_string(),
                EvidenceEcosystemBindingConfig {
                    profile: Some("odrl:v1".to_string()),
                    policy_id: "zeta-policy".to_string(),
                    policy_hash:
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_string(),
                    unsupported_odrl_terms: Vec::new(),
                },
            ),
        ]),
        claims: vec![claim],
        ..EvidenceConfig::default()
    });

    let results = runtime
        .evaluate(
            evidence,
            source,
            &store,
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "multi-policy-person-is-alive",
            ),
            None,
        )
        .await
        .expect("multi-source claim succeeds");

    let matching = results[0]
        .matching
        .as_ref()
        .expect("matching metadata is emitted");
    assert_eq!(matching.policy_id, "alpha-policy");
    assert_eq!(
        matching.policy_hash.as_deref(),
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(
        matching.evaluated_rule_ids,
        matching_policy_rule_ids(
            "person_alpha",
            &[
                "policy_identity",
                "odrl_terms",
                "purpose",
                "requested_fact",
                "requested_disclosure",
                "credential_format",
                "source_binding",
                "route_identity",
            ],
        )
    );
}

#[tokio::test]
async fn person_name_birthdate_ambiguous_and_no_match_are_stable_errors() {
    let runtime = RegistryNotaryRuntime::new();
    let evidence = evidence_config(vec![person_claim()]);
    let source = Arc::new(MatchingSource::new());
    let ambiguous = runtime
        .evaluate(
            Arc::clone(&evidence),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1975-05-05")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("distinct duplicate targets are ambiguous");
    assert_eq!(ambiguous.code(), "target.match_ambiguous");

    let not_found = runtime
        .evaluate(
            evidence,
            source,
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("No", "Match", Some("1999-01-01")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("missing target is not found");
    assert_eq!(not_found.code(), "target.not_found");
}

#[tokio::test]
async fn duplicate_rows_for_one_entity_do_not_make_ambiguous_match() {
    let runtime = RegistryNotaryRuntime::new();
    let results = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            Arc::new(MatchingSource::new()),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1980-01-01")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect("duplicate rows for one entity collapse to one match");
    assert_eq!(results[0].value, Some(json!(true)));
}

#[tokio::test]
async fn attribute_only_targets_get_distinct_opaque_handles() {
    let runtime = RegistryNotaryRuntime::new();
    let evidence = evidence_config(vec![person_claim()]);
    let first = runtime
        .evaluate(
            Arc::clone(&evidence),
            Arc::new(MatchingSource::new()),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect("first attribute target matches");
    let second = runtime
        .evaluate(
            evidence,
            Arc::new(MatchingSource::new()),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1980-01-01")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect("second attribute target matches");

    assert_ne!(first[0].target_ref.handle, second[0].target_ref.handle);
    assert!(first[0].target_ref.profile.is_none());
}

#[tokio::test]
async fn adapter_receives_unrestricted_context_when_allowed_inputs_are_empty() {
    let runtime = RegistryNotaryRuntime::new();
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching.allowed_target_inputs.clear();
    matching.allowed_requester_inputs.clear();

    let source = Arc::new(ContextRecordingSource::new());
    let mut target = person_target("Amina", "Diallo", Some("1984-02-10"));
    target
        .attributes
        .insert("private_note".to_string(), json!("do-not-forward"));
    target.profile = None;

    runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(target, "person-is-alive"),
            None,
        )
        .await
        .expect("evaluation succeeds with minimized adapter context");

    let seen = source.seen();
    assert_eq!(seen.target.entity_type, "Person");
    assert!(seen.target.attributes.contains_key("given_name"));
    assert!(seen.target.attributes.contains_key("family_name"));
    assert!(seen.target.attributes.contains_key("birthdate"));
    assert!(seen.target.attributes.contains_key("private_note"));
    assert!(seen.requester.is_none());
    assert!(seen.on_behalf_of.is_none());
}

#[tokio::test]
async fn adapter_receives_minimized_context_when_allowed_inputs_are_configured() {
    let runtime = RegistryNotaryRuntime::new();
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching.allowed_target_inputs = vec![
        "target.attributes.given_name".to_string(),
        "target.attributes.family_name".to_string(),
        "target.attributes.birthdate".to_string(),
    ];

    let source = Arc::new(ContextRecordingSource::new());
    let target = person_target("Amina", "Diallo", Some("1984-02-10"));

    runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(target, "person-is-alive"),
            None,
        )
        .await
        .expect("evaluation succeeds with minimized adapter context");

    let seen = source.seen();
    assert_eq!(seen.target.entity_type, "Person");
    assert!(seen.target.attributes.contains_key("given_name"));
    assert!(seen.target.attributes.contains_key("family_name"));
    assert!(seen.target.attributes.contains_key("birthdate"));
    assert_eq!(seen.target.attributes.len(), 3);
}

#[tokio::test]
async fn target_wildcard_allowlist_requires_segment_boundary() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching.allowed_target_inputs = vec![
        "target.attributes.given_name".to_string(),
        "target.attributes.family_name".to_string(),
        "target.attributes.birth.*".to_string(),
    ];

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("partial-segment target wildcard does not authorize birthdate");

    assert_eq!(error.code(), "target.matching_policy_rejected");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn default_context_batch_read_runs_concurrently_and_preserves_order() {
    let source = DelayedContextSource;
    let binding = SourceBindingConfig {
        connector: SourceConnectorKind::RegistryDataApi,
        connection: None,
        required_scope: None,
        dataset: "people".to_string(),
        entity: "person".to_string(),
        lookup: SourceLookupConfig {
            input: "target.id".to_string(),
            field: "id".to_string(),
            op: "eq".to_string(),
            cardinality: "one".to_string(),
        },
        query_fields: Vec::new(),
        fields: BTreeMap::new(),
        matching: SourceMatchingConfig::default(),
    };
    let bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)> = (0..4)
        .map(|idx| {
            let mut target = EvidenceEntity::new("Person");
            target.id = Some(format!("p-{idx}"));
            (
                binding.clone(),
                EvidenceRequestContext {
                    requester: None,
                    target,
                    relationship: None,
                    on_behalf_of: None,
                },
            )
        })
        .collect();

    let started = Instant::now();
    let results = source.read_many_context(bindings, "benefits").await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(160),
        "four 50ms context reads should overlap; elapsed={elapsed:?}"
    );
    let ids: Vec<String> = results
        .into_iter()
        .map(|result| {
            result.expect("read succeeds")["id"]
                .as_str()
                .expect("id is a string")
                .to_string()
        })
        .collect();
    assert_eq!(ids, vec!["p-0", "p-1", "p-2", "p-3"]);
}

#[tokio::test]
async fn adapter_minimization_retains_configured_requester_and_relationship_paths() {
    let runtime = RegistryNotaryRuntime::new();
    let mut claim = person_claim();
    let binding = claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists");
    binding.lookup.input = "relationship.attributes.case_id".to_string();
    binding.matching.allowed_requester_inputs = vec![
        "requester.identifiers.worker_id".to_string(),
        "requester.attributes.office".to_string(),
    ];
    binding.matching.allowed_relationships = vec!["case_worker".to_string()];

    let source = Arc::new(ContextRecordingSource::new());
    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    let mut requester = EvidenceEntity::with_identifier("Person", "worker_id", "case-worker-1");
    requester
        .attributes
        .insert("office".to_string(), json!("district-7"));
    request.requester = Some(requester);
    request.relationship = Some(EvidenceRelationship {
        relationship_type: "case_worker".to_string(),
        attributes: BTreeMap::from([
            ("case_id".to_string(), json!("case-123")),
            ("internal_note".to_string(), json!("do-not-forward")),
        ]),
    });

    runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect("evaluation succeeds with minimized requester and relationship context");

    let seen = source.seen();
    let requester = seen.requester.expect("requester context is forwarded");
    assert_eq!(requester.entity_type, "Person");
    assert_eq!(
        requester.identifier_value("worker_id"),
        Some("case-worker-1")
    );
    assert_eq!(
        requester.attributes.get("office"),
        Some(&json!("district-7"))
    );
    let relationship = seen
        .relationship
        .expect("relationship context is forwarded");
    assert_eq!(relationship.relationship_type, "case_worker");
    assert_eq!(
        relationship.attributes.get("case_id"),
        Some(&json!("case-123"))
    );
    assert!(!relationship.attributes.contains_key("internal_note"));
    assert!(seen.on_behalf_of.is_none());
}

#[tokio::test]
async fn requester_overprovision_is_rejected_before_adapter_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .allowed_requester_inputs = vec!["requester.attributes.office".to_string()];

    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    let mut requester = EvidenceEntity::new("Person");
    requester
        .attributes
        .insert("office".to_string(), json!("district-7"));
    requester
        .attributes
        .insert("private_note".to_string(), json!("do-not-forward"));
    request.requester = Some(requester);

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect_err("over-provisioned requester context is rejected");

    assert_eq!(error.code(), "requester.matching_policy_rejected");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn requester_wildcard_allowlist_requires_segment_boundary() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .allowed_requester_inputs = vec!["requester.attributes.off.*".to_string()];

    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    let mut requester = EvidenceEntity::new("Person");
    requester
        .attributes
        .insert("office".to_string(), json!("district-7"));
    request.requester = Some(requester);

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect_err("partial-segment requester wildcard does not authorize office");

    assert_eq!(error.code(), "requester.matching_policy_rejected");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn profile_gate_rejects_missing_inputs_and_disallowed_purpose_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let missing = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(person_target("Amina", "Diallo", None), "person-is-alive"),
            None,
        )
        .await
        .expect_err("missing birthdate is insufficient");
    assert_eq!(missing.code(), "target.attributes_insufficient");
    assert_eq!(source.reads(), 0);

    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    request.purpose = Some("marketing".to_string());
    let denied = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect_err("purpose gate rejects request");
    assert_eq!(denied.code(), "pdp.purpose_not_permitted");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn assurance_policy_rejects_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .allowed_assurance = vec!["substantial".to_string()];
    let mut target = person_target("Amina", "Diallo", Some("1984-02-10"));
    target.assurance = Some(EvidenceAssurance {
        method: None,
        level_scheme: None,
        level: Some("substantial".to_string()),
        verified_at: None,
        issuer: None,
        evidence: Vec::new(),
    });

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(target, "person-is-alive"),
            None,
        )
        .await
        .expect_err("self-asserted assurance rejects request");

    assert_eq!(error.code(), "pdp.assurance_insufficient");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn assurance_policy_accepts_trusted_authorization_details() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .allowed_assurance = vec!["substantial".to_string()];
    let principal = principal_with_policy_context(Some("substantial"), None, None, None);

    let results = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal,
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect("trusted assurance permits source read");

    assert_eq!(results[0].value, Some(json!(true)));
    assert_eq!(source.reads(), 1);
}

#[tokio::test]
async fn context_only_authorization_details_supply_policy_context_without_transaction_scope() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching.allowed_assurance = vec!["substantial".to_string()];
    matching.permitted_jurisdictions = vec!["ZZ".to_string()];
    matching.require_legal_basis = true;
    matching.require_consent = true;
    let principal = principal_with_context_only_policy_context(
        Some("substantial"),
        Some("ZZ"),
        Some("demo:casework"),
        Some("demo:consent"),
    );

    let results = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal,
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect("context-only policy details permit source read");

    assert_eq!(results[0].value, Some(json!(true)));
    assert_eq!(source.reads(), 1);
}

#[tokio::test]
async fn context_only_authorization_details_missing_consent_reject_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching.allowed_assurance = vec!["substantial".to_string()];
    matching.permitted_jurisdictions = vec!["ZZ".to_string()];
    matching.require_legal_basis = true;
    matching.require_consent = true;
    let principal = principal_with_context_only_policy_context(
        Some("substantial"),
        Some("ZZ"),
        Some("demo:casework"),
        None,
    );

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal,
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("context-only details without consent still fail PDP gates");

    assert_eq!(error.code(), "pdp.consent_required");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn source_policy_rejects_broadened_authorization_details_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .allowed_assurance = vec!["substantial".to_string()];
    let mut principal = principal_with_policy_context(Some("substantial"), None, None, None);
    principal
        .authorization_details
        .as_mut()
        .expect("authorization details exist")
        .claims
        .push(ClaimRef::with_version("date-of-birth", "1.0.0"));

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal,
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("broadened authorization_details must reject before source read");

    assert_eq!(error.code(), "target.matching_policy_rejected");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn source_policy_rejects_duplicate_authorization_action_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .allowed_assurance = vec!["substantial".to_string()];
    let mut principal = principal_with_policy_context(Some("substantial"), None, None, None);
    principal
        .authorization_details
        .as_mut()
        .expect("authorization details exist")
        .actions
        .push("evaluate".to_string());

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal,
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("duplicate authorization_details action must reject before source read");

    assert_eq!(error.code(), "target.matching_policy_rejected");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn source_policy_rejects_claim_mismatched_authorization_details_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .allowed_assurance = vec!["substantial".to_string()];
    let mut principal = principal_with_policy_context(Some("substantial"), None, None, None);
    principal
        .authorization_details
        .as_mut()
        .expect("authorization details exist")
        .claims = vec![ClaimRef::with_version("date-of-birth", "1.0.0")];

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal,
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("claim-mismatched authorization_details must reject before source read");

    assert_eq!(error.code(), "target.matching_policy_rejected");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn batch_prefetch_rejects_broadened_authorization_details_before_bulk_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(BatchContextRecordingSource::new());
    let mut claim = person_claim();
    let binding = claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists");
    binding.connector = SourceConnectorKind::SourceAdapterSidecar;
    binding.connection = Some("source_adapter_crvs".to_string());
    binding.matching.allowed_assurance = vec!["substantial".to_string()];

    let mut principal = principal_with_policy_context(Some("substantial"), None, None, None);
    principal
        .authorization_details
        .as_mut()
        .expect("authorization details exist")
        .claims
        .push(ClaimRef::with_version("date-of-birth", "1.0.0"));

    let response = runtime
        .batch_evaluate(
            evidence_config_with_source_adapter_batch_connection(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal,
            BatchEvaluateRequest {
                items: vec![BatchEvaluateItemRequest {
                    requester: None,
                    target: person_target("Amina", "Diallo", Some("1984-02-10")),
                    relationship: Some(EvidenceRelationship {
                        relationship_type: "self".to_string(),
                        attributes: BTreeMap::new(),
                    }),
                    on_behalf_of: None,
                    purpose: Some("benefits".to_string()),
                }],
                claims: vec![ClaimRef::new("person-is-alive")],
                disclosure: Some("value".to_string()),
                format: None,
                purpose: None,
            },
            BatchEvaluateOptions::default(),
        )
        .await
        .expect("batch returns per-item authorization failure");

    assert_eq!(source.read_many_calls(), 0);
    assert_eq!(source.read_one_calls(), 0);
    assert_eq!(response.summary.succeeded, 0);
    assert_eq!(response.summary.failed, 1);
    assert_eq!(
        response.items[0].errors[0].code,
        "target.matching_policy_rejected"
    );
}

#[tokio::test]
async fn minimum_assurance_policy_rejects_before_source_read_and_accepts_higher_rank() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .minimum_assurance = Some("substantial".to_string());
    let low_principal = principal_with_policy_context(Some("low"), None, None, None);

    let error = runtime
        .evaluate(
            evidence_config(vec![claim.clone()]),
            source.clone(),
            &EvidenceStore::default(),
            &low_principal,
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("low assurance rejects substantial floor");

    assert_eq!(error.code(), "pdp.assurance_insufficient");
    assert_eq!(source.reads(), 0);

    let high_principal = principal_with_policy_context(Some("high"), None, None, None);
    let results = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &high_principal,
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect("high assurance satisfies substantial floor");

    assert_eq!(results[0].value, Some(json!(true)));
    assert_eq!(source.reads(), 1);
}

#[tokio::test]
async fn redaction_policy_forces_redacted_value_disclosure() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim.disclosure.allowed.push("redacted".to_string());
    claim.disclosure.downgrade = "redacted".to_string();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .redaction_fields = vec!["value".to_string()];

    let results = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect("redaction permit still evaluates claim");

    assert_eq!(results[0].disclosure, "redacted");
    assert_eq!(results[0].value, None);
    assert_eq!(results[0].satisfied, None);
    assert_eq!(source.reads(), 1);
}

#[tokio::test]
async fn redaction_policy_fails_closed_when_redacted_disclosure_is_not_allowed() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .redaction_fields = vec!["value".to_string()];

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("redaction must not leak through value-only disclosure");

    assert_eq!(error.code(), "claim.disclosure_not_allowed");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn requested_disclosure_denies_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim.disclosure.allowed = vec!["value".to_string()];
    claim.disclosure.downgrade = "deny".to_string();
    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    request.disclosure = Some("predicate".to_string());

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect_err("requested disclosure is denied before source read");

    assert_eq!(error.code(), "claim.disclosure_not_allowed");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn requested_format_denies_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    request.format = Some("application/unsupported".to_string());

    let error = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect_err("requested format is denied before source read");

    assert_eq!(error.code(), "claim.format_not_supported");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn object_field_redaction_remains_value_disclosure() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(ObjectProfileSource::new());
    let mut claim = person_profile_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .redaction_fields = vec!["birthdate".to_string()];

    let results = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-profile",
            ),
            None,
        )
        .await
        .expect("top-level object field redaction evaluates as value disclosure");

    assert_eq!(results[0].disclosure, "value");
    assert_eq!(source.reads(), 1);
    assert_eq!(
        results[0].value,
        Some(json!({
            "given_name": "Amina",
            "family_name": "Diallo"
        }))
    );
}

#[tokio::test]
async fn unmappable_object_redaction_fails_closed_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(ObjectProfileSource::new());
    let mut claim = person_profile_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .redaction_fields = vec!["profile.birthdate".to_string()];

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-profile",
            ),
            None,
        )
        .await
        .expect_err("path-like object redaction cannot be carried by value disclosure");

    assert_eq!(error.code(), "claim.disclosure_not_allowed");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn jurisdiction_policy_rejects_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .permitted_jurisdictions = vec!["RW".to_string()];
    let mut target = person_target("Amina", "Diallo", Some("1984-02-10"));
    target.identifiers.push(EvidenceIdentifier {
        scheme: "national_id".to_string(),
        value: "NAT-123".to_string(),
        issuer: None,
        country: Some("RW".to_string()),
    });

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(target, "person-is-alive"),
            None,
        )
        .await
        .expect_err("self-asserted jurisdiction rejects request");

    assert_eq!(error.code(), "pdp.jurisdiction_not_permitted");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn jurisdiction_legal_basis_and_consent_accept_trusted_authorization_details() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching.permitted_jurisdictions = vec!["RW".to_string()];
    matching.require_legal_basis = true;
    matching.require_consent = true;
    let principal = principal_with_policy_context(
        None,
        Some("RW"),
        Some("legal-basis:benefits"),
        Some("consent:person-1"),
    );

    let results = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal,
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect("trusted jurisdiction, legal basis, and consent permit source read");

    assert_eq!(results[0].value, Some(json!(true)));
    assert_eq!(source.reads(), 1);
}

#[tokio::test]
async fn required_legal_basis_and_consent_reject_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching.require_legal_basis = true;
    matching.require_consent = true;

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("missing legal basis and consent reject request");

    assert_eq!(error.code(), "pdp.legal_basis_required");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn required_consent_rejects_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching.require_legal_basis = true;
    matching.require_consent = true;
    let principal = principal_with_policy_context(None, None, Some("legal-basis:benefits"), None);

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal,
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("missing consent rejects request");

    assert_eq!(error.code(), "pdp.consent_required");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn unsupported_selected_odrl_terms_reject_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .ecosystem_binding = Some(EcosystemBindingSelectorConfig {
        id: Some("civil-pack".to_string()),
        ..EcosystemBindingSelectorConfig::default()
    });
    let mut evidence = (*evidence_config(vec![claim])).clone();
    evidence.ecosystem_bindings.insert(
        "civil-pack".to_string(),
        EvidenceEcosystemBindingConfig {
            profile: Some("registry-notary/source-policy/v1".to_string()),
            policy_id: "evidence-pack-policy".to_string(),
            policy_hash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
            unsupported_odrl_terms: vec!["odrl:targetPolicy".to_string()],
        },
    );

    let error = runtime
        .evaluate(
            Arc::new(evidence),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("unsupported selected ODRL term rejects before source read");

    assert_eq!(error.code(), "pdp.unsupported_policy_term");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn purpose_rejection_precedes_matching_policy_rejection() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    request.target.as_mut().expect("target present").entity_type = "Animal".to_string();
    request.purpose = Some("marketing".to_string());

    let error = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect_err("purpose gate wins over matching policy");

    assert_eq!(error.code(), "pdp.purpose_not_permitted");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn deployment_purpose_allow_list_rejects_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .allowed_purposes
        .clear();
    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    request.purpose = Some("marketing".to_string());

    let error = runtime
        .evaluate(
            evidence_config_with_allowed_purposes(vec![claim], vec!["benefits".to_string()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect_err("deployment purpose allow-list rejects request");

    assert_eq!(error.code(), "pdp.purpose_not_permitted");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn claim_purpose_rejects_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim.purpose = Some("benefits".to_string());
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .allowed_purposes
        .clear();
    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    request.purpose = Some("marketing".to_string());

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect_err("claim purpose rejects request");

    assert_eq!(error.code(), "pdp.purpose_not_permitted");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn empty_target_is_rejected_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());

    let error = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(EvidenceEntity::new("Person"), "person-is-alive"),
            None,
        )
        .await
        .expect_err("empty target has no matching input");

    assert_eq!(error.code(), "target.attributes_insufficient");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn machine_evaluate_without_target_is_rejected_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());

    let error = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            EvaluateRequest {
                requester: None,
                target: None,
                relationship: None,
                on_behalf_of: None,
                claims: vec![ClaimRef::new("person-is-alive")],
                disclosure: None,
                format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
                purpose: Some("benefits_eligibility".to_string()),
            },
            None,
        )
        .await
        .expect_err("machine evaluation requires a target");

    assert_eq!(error.code(), "request.invalid");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn profile_gate_uses_specific_identifier_and_policy_problem_codes() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut land_without_identifier = EvidenceEntity::new("LandParcel");
    land_without_identifier
        .attributes
        .insert("district".to_string(), json!("north"));
    let missing_identifier = runtime
        .evaluate(
            evidence_config(vec![parcel_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(land_without_identifier, "land-parcel-is-registered"),
            None,
        )
        .await
        .expect_err("missing identifier is specific");
    assert_eq!(missing_identifier.code(), "target.identifier_missing");
    assert_eq!(source.reads(), 0);

    let mut wrong_type_target = EvidenceEntity::new("Person");
    wrong_type_target
        .attributes
        .insert("district".to_string(), json!("north"));
    let wrong_target_type = runtime
        .evaluate(
            evidence_config(vec![parcel_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(wrong_type_target, "land-parcel-is-registered"),
            None,
        )
        .await
        .expect_err("wrong target type is rejected by policy");
    assert_eq!(wrong_target_type.code(), "target.matching_policy_rejected");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn profile_gate_covers_requester_relationship_and_state_outcomes() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .require_requester_reauthentication = true;
    let reauth = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Amina", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("reauthentication gate rejects before source read");
    assert_eq!(reauth.code(), "requester.reauthentication_required");
    assert_eq!(source.reads(), 0);

    let mut no_relationship = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    no_relationship.relationship = None;
    let missing_relationship = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            no_relationship,
            None,
        )
        .await
        .expect_err("missing relationship is specific");
    assert_eq!(
        missing_relationship.code(),
        "pdp.relationship_not_permitted"
    );
    assert_eq!(source.reads(), 0);

    let mut wrong_relationship = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    wrong_relationship.relationship = Some(EvidenceRelationship {
        relationship_type: "guardian".to_string(),
        attributes: BTreeMap::new(),
    });
    let rejected_relationship = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            wrong_relationship,
            None,
        )
        .await
        .expect_err("relationship policy rejects wrong relationship");
    assert_eq!(
        rejected_relationship.code(),
        "pdp.relationship_not_permitted"
    );
    assert_eq!(source.reads(), 0);

    let invalid_state = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Inactive", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("invalid state is surfaced");
    assert_eq!(invalid_state.code(), "target.not_in_valid_state");

    let low_confidence = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source,
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("Low", "Diallo", Some("1984-02-10")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("low confidence is surfaced");
    assert_eq!(low_confidence.code(), "target.match_low_confidence");
}

#[tokio::test]
async fn unscoped_relationship_policy_allows_any_allowed_purpose() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching
        .allowed_purposes
        .push("benefits_renewal".to_string());

    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    request.purpose = Some("benefits_renewal".to_string());

    runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect("flat relationship allow-list remains unscoped by default");

    assert_eq!(source.reads(), 1);
}

#[tokio::test]
async fn scoped_relationship_policy_allows_configured_purpose() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching
        .allowed_purposes
        .push("school_enrollment".to_string());
    matching.allowed_relationships.push("guardian".to_string());
    matching.relationship_purpose_scopes =
        BTreeMap::from([("guardian".to_string(), vec!["benefits".to_string()])]);

    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    request.relationship = Some(EvidenceRelationship {
        relationship_type: "guardian".to_string(),
        attributes: BTreeMap::new(),
    });

    runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect("guardian relationship is allowed for the scoped purpose");

    assert_eq!(source.reads(), 1);
}

#[tokio::test]
async fn scoped_relationship_policy_rejects_unconfigured_purpose_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching
        .allowed_purposes
        .push("school_enrollment".to_string());
    matching.allowed_relationships.push("guardian".to_string());
    matching.relationship_purpose_scopes =
        BTreeMap::from([("guardian".to_string(), vec!["benefits".to_string()])]);

    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    request.purpose = Some("school_enrollment".to_string());
    request.relationship = Some(EvidenceRelationship {
        relationship_type: "guardian".to_string(),
        attributes: BTreeMap::new(),
    });

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect_err("guardian relationship is not allowed for school enrollment");

    assert_eq!(error.code(), "pdp.purpose_not_permitted");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn scoped_relationship_policy_requires_flat_relationship_allowlist() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching.relationship_purpose_scopes =
        BTreeMap::from([("guardian".to_string(), vec!["benefits".to_string()])]);

    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    request.relationship = Some(EvidenceRelationship {
        relationship_type: "guardian".to_string(),
        attributes: BTreeMap::new(),
    });

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect_err("scopes narrow the flat relationship allow-list");

    assert_eq!(error.code(), "pdp.relationship_not_permitted");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn unsupported_profile_context_is_rejected_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut target = person_target("Amina", "Diallo", Some("1984-02-10"));
    target.profile = Some("unknown-profile".to_string());
    let error = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(target, "person-is-alive"),
            None,
        )
        .await
        .expect_err("unsupported profiles fail closed");

    assert_eq!(error.code(), "profile.unsupported");
    assert_eq!(source.reads(), 0);

    let mut delegated = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    delegated.on_behalf_of = Some(registry_notary_core::EvidenceOnBehalfOf {
        actor: registry_notary_core::EvidenceActor {
            actor_type: "operator".to_string(),
            id_hash: "hmac-sha256:represented-1".to_string(),
            assurance: None,
        },
        delegation_ref: None,
    });
    let delegated_error = runtime
        .evaluate(
            evidence_config(vec![person_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            delegated,
            None,
        )
        .await
        .expect_err("reserved on_behalf_of context fails closed");

    assert_eq!(delegated_error.code(), "profile.unsupported");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn profile_can_collapse_matching_oracle_errors() {
    let runtime = RegistryNotaryRuntime::new();
    let mut claim = person_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .collapse_matching_errors = true;

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            Arc::new(MatchingSource::new()),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(
                person_target("No", "Match", Some("1999-01-01")),
                "person-is-alive",
            ),
            None,
        )
        .await
        .expect_err("matching failure is collapsed");

    assert_eq!(error.code(), "evidence.not_available");
    assert_eq!(error.audit_code(), "target.not_found");

    let mut claim = person_claim();
    let matching = &mut claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching;
    matching.collapse_matching_errors = true;
    matching
        .allowed_purposes
        .push("school_enrollment".to_string());
    matching.allowed_relationships.push("guardian".to_string());
    matching.relationship_purpose_scopes =
        BTreeMap::from([("guardian".to_string(), vec!["benefits".to_string()])]);
    let mut request = evaluate_request(
        person_target("Amina", "Diallo", Some("1984-02-10")),
        "person-is-alive",
    );
    request.purpose = Some("school_enrollment".to_string());
    request.relationship = Some(EvidenceRelationship {
        relationship_type: "guardian".to_string(),
        attributes: BTreeMap::new(),
    });

    let error = runtime
        .evaluate(
            evidence_config(vec![claim]),
            Arc::new(MatchingSource::new()),
            &EvidenceStore::default(),
            &principal(),
            request,
            None,
        )
        .await
        .expect_err("relationship purpose failure is denied");

    assert_eq!(error.code(), "pdp.purpose_not_permitted");
    assert_eq!(error.audit_code(), "pdp.purpose_not_permitted");
}

#[tokio::test]
async fn land_parcel_identifier_target_succeeds() {
    let runtime = RegistryNotaryRuntime::new();
    let results = runtime
        .evaluate(
            evidence_config(vec![parcel_claim()]),
            Arc::new(MatchingSource::new()),
            &EvidenceStore::default(),
            &principal(),
            evaluate_request(land_target("PARCEL-8891"), "land-parcel-is-registered"),
            None,
        )
        .await
        .expect("land parcel identifier match succeeds");

    assert_eq!(results[0].value, Some(json!(true)));
    assert_eq!(results[0].target_ref.entity_type, "LandParcel");
    assert_eq!(
        results[0].target_ref.identifier_schemes,
        vec!["cadastral_reference".to_string()]
    );
}

#[tokio::test]
async fn batch_supports_same_rich_item_model() {
    let runtime = RegistryNotaryRuntime::new();
    let response = runtime
        .batch_evaluate(
            evidence_config(vec![parcel_claim()]),
            Arc::new(MatchingSource::new()),
            &EvidenceStore::default(),
            &principal(),
            BatchEvaluateRequest {
                items: vec![
                    BatchEvaluateItemRequest {
                        requester: None,
                        target: land_target("PARCEL-8891"),
                        relationship: None,
                        on_behalf_of: None,
                        purpose: Some("benefits".to_string()),
                    },
                    BatchEvaluateItemRequest {
                        requester: None,
                        target: land_target("PARCEL-404"),
                        relationship: None,
                        on_behalf_of: None,
                        purpose: Some("benefits".to_string()),
                    },
                ],
                claims: vec![ClaimRef::new("land-parcel-is-registered")],
                disclosure: Some("value".to_string()),
                format: None,
                purpose: None,
            },
            BatchEvaluateOptions::default(),
        )
        .await
        .expect("batch completes with per-item outcome");

    assert_eq!(response.summary.succeeded, 1);
    assert_eq!(response.summary.failed, 1);
    assert_eq!(response.items[0].target_ref.entity_type, "LandParcel");
    assert_eq!(response.items[1].errors[0].code, "target.not_found");
}

#[tokio::test]
async fn batch_prefetch_minimizes_context_and_excludes_policy_rejected_items() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(BatchContextRecordingSource::new());
    let mut claim = person_claim();
    let binding = claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists");
    binding.connector = SourceConnectorKind::SourceAdapterSidecar;
    binding.connection = Some("source_adapter_crvs".to_string());
    binding.query_fields = vec![
        SourceQueryFieldConfig {
            input: "target.attributes.given_name".to_string(),
            field: "given_name".to_string(),
            op: "eq".to_string(),
        },
        SourceQueryFieldConfig {
            input: "target.attributes.family_name".to_string(),
            field: "family_name".to_string(),
            op: "eq".to_string(),
        },
        SourceQueryFieldConfig {
            input: "target.attributes.birthdate".to_string(),
            field: "birthdate".to_string(),
            op: "eq".to_string(),
        },
    ];
    binding.matching.allowed_target_inputs = vec![
        "target.attributes.given_name".to_string(),
        "target.attributes.family_name".to_string(),
        "target.attributes.birthdate".to_string(),
    ];

    let valid = person_target("Amina", "Diallo", Some("1984-02-10"));
    let mut rejected = person_target("Amina", "Diallo", Some("1984-02-10"));
    rejected
        .attributes
        .insert("private_note".to_string(), json!("do-not-forward"));

    let response = runtime
        .batch_evaluate(
            evidence_config_with_source_adapter_batch_connection(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            BatchEvaluateRequest {
                items: vec![
                    BatchEvaluateItemRequest {
                        requester: None,
                        target: valid,
                        relationship: Some(EvidenceRelationship {
                            relationship_type: "self".to_string(),
                            attributes: BTreeMap::new(),
                        }),
                        on_behalf_of: None,
                        purpose: Some("benefits".to_string()),
                    },
                    BatchEvaluateItemRequest {
                        requester: None,
                        target: rejected,
                        relationship: Some(EvidenceRelationship {
                            relationship_type: "self".to_string(),
                            attributes: BTreeMap::new(),
                        }),
                        on_behalf_of: None,
                        purpose: Some("benefits".to_string()),
                    },
                ],
                claims: vec![ClaimRef::new("person-is-alive")],
                disclosure: Some("value".to_string()),
                format: None,
                purpose: None,
            },
            BatchEvaluateOptions::default(),
        )
        .await
        .expect("batch completes with per-item outcomes");

    assert_eq!(source.read_many_calls(), 1);
    assert_eq!(source.read_one_calls(), 0);
    let batches = source.seen_batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(
        batches[0].len(),
        1,
        "only the policy-valid item is prefetched"
    );
    let seen = &batches[0][0];
    assert!(seen.target.attributes.contains_key("given_name"));
    assert!(seen.target.attributes.contains_key("family_name"));
    assert!(seen.target.attributes.contains_key("birthdate"));
    assert!(!seen.target.attributes.contains_key("private_note"));
    assert!(seen.requester.is_none());
    assert!(seen.on_behalf_of.is_none());

    assert!(matches!(
        response.items[0].status,
        registry_notary_core::BatchItemStatus::Succeeded
    ));
    assert_eq!(
        response.items[1].errors[0].code,
        "target.matching_policy_rejected"
    );
}

#[tokio::test]
async fn batch_memo_key_includes_minimized_requester_context() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(RequesterSensitiveBatchSource::new());
    let mut claim = claim(
        "requester-sensitive-alive",
        "person",
        "alive",
        "Person",
        SourceMatchingConfig {
            allowed_purposes: vec!["benefits".to_string()],
            allowed_requester_inputs: vec!["requester.attributes.office".to_string()],
            ..SourceMatchingConfig::default()
        },
    );
    let binding = claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists");
    binding.connector = SourceConnectorKind::SourceAdapterSidecar;
    binding.connection = Some("source_adapter_crvs".to_string());

    let response = runtime
        .batch_evaluate(
            evidence_config_with_source_adapter_batch_connection(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            BatchEvaluateRequest {
                items: vec![
                    BatchEvaluateItemRequest {
                        requester: Some(requester_with_office("north")),
                        target: observed_person_target(),
                        relationship: None,
                        on_behalf_of: None,
                        purpose: Some("benefits".to_string()),
                    },
                    BatchEvaluateItemRequest {
                        requester: Some(requester_with_office("south")),
                        target: observed_person_target(),
                        relationship: None,
                        on_behalf_of: None,
                        purpose: Some("benefits".to_string()),
                    },
                ],
                claims: vec![ClaimRef::new("requester-sensitive-alive")],
                disclosure: Some("value".to_string()),
                format: None,
                purpose: None,
            },
            BatchEvaluateOptions::default(),
        )
        .await
        .expect("batch completes with requester-sensitive outcomes");

    assert_eq!(source.read_many_calls(), 1);
    assert_eq!(source.read_one_calls(), 0);
    assert_eq!(response.summary.succeeded, 2);
    assert_eq!(response.items[0].claim_results[0].value, Some(json!(true)));
    assert_eq!(response.items[1].claim_results[0].value, Some(json!(false)));

    let batches = source.seen_batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].len(), 2);
    assert_eq!(
        batches[0][0]
            .requester
            .as_ref()
            .and_then(|requester| requester.attributes.get("office")),
        Some(&json!("north"))
    );
    assert_eq!(
        batches[0][1]
            .requester
            .as_ref()
            .and_then(|requester| requester.attributes.get("office")),
        Some(&json!("south"))
    );
}

#[tokio::test]
async fn batch_redaction_prefetch_skips_unmappable_value_disclosure() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(BatchContextRecordingSource::new());
    let mut claim = person_profile_claim();
    let binding = claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists");
    binding.connector = SourceConnectorKind::SourceAdapterSidecar;
    binding.connection = Some("source_adapter_crvs".to_string());
    binding.query_fields = vec![
        SourceQueryFieldConfig {
            input: "target.attributes.given_name".to_string(),
            field: "given_name".to_string(),
            op: "eq".to_string(),
        },
        SourceQueryFieldConfig {
            input: "target.attributes.family_name".to_string(),
            field: "family_name".to_string(),
            op: "eq".to_string(),
        },
        SourceQueryFieldConfig {
            input: "target.attributes.birthdate".to_string(),
            field: "birthdate".to_string(),
            op: "eq".to_string(),
        },
    ];
    binding.matching.redaction_fields = vec!["profile.birthdate".to_string()];

    let response = runtime
        .batch_evaluate(
            evidence_config_with_source_adapter_batch_connection(vec![claim]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            BatchEvaluateRequest {
                items: vec![BatchEvaluateItemRequest {
                    requester: None,
                    target: person_target("Amina", "Diallo", Some("1984-02-10")),
                    relationship: Some(EvidenceRelationship {
                        relationship_type: "self".to_string(),
                        attributes: BTreeMap::new(),
                    }),
                    on_behalf_of: None,
                    purpose: Some("benefits".to_string()),
                }],
                claims: vec![ClaimRef::new("person-profile")],
                disclosure: Some("value".to_string()),
                format: None,
                purpose: None,
            },
            BatchEvaluateOptions::default(),
        )
        .await
        .expect("batch completes with per-item disclosure outcome");

    assert_eq!(source.read_many_calls(), 0);
    assert_eq!(source.read_one_calls(), 0);
    assert!(matches!(
        response.items[0].status,
        registry_notary_core::BatchItemStatus::Failed
    ));
    assert_eq!(
        response.items[0].errors[0].code,
        "claim.disclosure_not_allowed"
    );
}

#[tokio::test]
async fn batch_rejects_empty_item_target_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());

    let error = runtime
        .batch_evaluate(
            evidence_config(vec![parcel_claim()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            BatchEvaluateRequest {
                items: vec![BatchEvaluateItemRequest {
                    requester: None,
                    target: EvidenceEntity::new("LandParcel"),
                    relationship: None,
                    on_behalf_of: None,
                    purpose: Some("benefits".to_string()),
                }],
                claims: vec![ClaimRef::new("land-parcel-is-registered")],
                disclosure: Some("value".to_string()),
                format: None,
                purpose: None,
            },
            BatchEvaluateOptions::default(),
        )
        .await
        .expect_err("empty item target has no matching input");

    assert_eq!(error.code(), "target.attributes_insufficient");
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn batch_rejects_deployment_purpose_before_source_read() {
    let runtime = RegistryNotaryRuntime::new();
    let source = Arc::new(MatchingSource::new());
    let mut claim = parcel_claim();
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .allowed_purposes
        .clear();

    let response = runtime
        .batch_evaluate(
            evidence_config_with_allowed_purposes(vec![claim], vec!["benefits".to_string()]),
            source.clone(),
            &EvidenceStore::default(),
            &principal(),
            BatchEvaluateRequest {
                items: vec![BatchEvaluateItemRequest {
                    requester: None,
                    target: land_target("PARCEL-8891"),
                    relationship: None,
                    on_behalf_of: None,
                    purpose: Some("marketing".to_string()),
                }],
                claims: vec![ClaimRef::new("land-parcel-is-registered")],
                disclosure: Some("value".to_string()),
                format: None,
                purpose: None,
            },
            BatchEvaluateOptions::default(),
        )
        .await
        .expect("deployment purpose allow-list rejects batch item");

    assert_eq!(response.summary.failed, 1);
    assert_eq!(
        response.items[0].errors[0].code,
        "pdp.purpose_not_permitted"
    );
    assert_eq!(source.reads(), 0);
}

#[tokio::test]
async fn batch_rejects_item_purpose_that_conflicts_with_batch_purpose() {
    let runtime = RegistryNotaryRuntime::new();
    let error = runtime
        .batch_evaluate(
            evidence_config(vec![parcel_claim()]),
            Arc::new(MatchingSource::new()),
            &EvidenceStore::default(),
            &principal(),
            BatchEvaluateRequest {
                items: vec![BatchEvaluateItemRequest {
                    requester: None,
                    target: land_target("PARCEL-8891"),
                    relationship: None,
                    on_behalf_of: None,
                    purpose: Some("marketing".to_string()),
                }],
                claims: vec![ClaimRef::new("land-parcel-is-registered")],
                disclosure: Some("value".to_string()),
                format: None,
                purpose: Some("benefits".to_string()),
            },
            BatchEvaluateOptions::default(),
        )
        .await
        .expect_err("conflicting purpose is rejected");

    assert_eq!(error.code(), "request.invalid");
}
