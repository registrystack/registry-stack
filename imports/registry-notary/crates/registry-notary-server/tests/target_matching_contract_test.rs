// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use registry_notary_core::{
    AccessMode, BatchEvaluateItemRequest, BatchEvaluateRequest, BatchOperationConfig,
    ClaimDefinition, ClaimOperationsConfig, ClaimRef, ClaimValueConfig, DisclosureConfig,
    EvaluateRequest, EvidenceConfig, EvidenceEntity, EvidenceError, EvidencePrincipal,
    EvidenceRelationship, EvidenceRequestContext, OperationConfig, RuleConfig, SourceBindingConfig,
    SourceConnectorKind, SourceFieldConfig, SourceLookupConfig, SourceMatchingConfig,
    SubjectRequest, FORMAT_CLAIM_RESULT_JSON,
};
use registry_notary_server::{
    BatchEvaluateOptions, EvidenceStore, RegistryNotaryRuntime, SourceReader,
};
use serde_json::{json, Value};

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
struct DelayedContextSource;

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
        inline_batch_limit: 20,
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
        principal_id: "client".to_string(),
        scopes: Vec::new(),
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
    }
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
    assert_eq!(source.reads(), 1);
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
    assert_eq!(denied.code(), "purpose.not_allowed");
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

    assert_eq!(error.code(), "purpose.not_allowed");
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

    assert_eq!(error.code(), "purpose.not_allowed");
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

    assert_eq!(error.code(), "purpose.not_allowed");
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
    assert_eq!(missing_relationship.code(), "relationship.not_established");
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
    assert_eq!(rejected_relationship.code(), "relationship.policy_rejected");
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
    delegated.on_behalf_of = Some(json!({"type": "Person", "id": "represented-1"}));
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

    let error = runtime
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
        .expect_err("deployment purpose allow-list rejects batch");

    assert_eq!(error.code(), "purpose.not_allowed");
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
