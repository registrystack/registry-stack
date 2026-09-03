// SPDX-License-Identifier: Apache-2.0

use registry_relay_v2::compiler::{classification_inventory_digest, compile_contract};
use registry_relay_v2::contract::{
    ClassificationReviewDocument, DataType, GeneratedIdentificationBinding, IdentificationMethod,
    PartialStringReveal, RegistryContract, ReviewStatus,
};
use registry_relay_v2::identification::{
    access_profile_report, classification_inventory_report, classification_review_starter,
    contextual_review_findings, core_pack_reference, identification_report_digest,
    identify_contract, parse_classification_review_yaml, render_access_profile_report,
    render_classification_inventory_report, render_classification_review_yaml,
    render_contextual_review_findings, render_identification_report,
    validate_classification_review, CategoricalConfidence, ClassificationReviewExpectation,
    IdentificationError, IdentificationStatus, TechnicalRole, REVIEWED_IDENTIFICATION_REPORT_PATH,
};
use registry_relay_v2::model::{
    CompileProfile, CompiledSelector, CompiledTransform, ObservedColumn, ObservedSourceSchema,
    ObservedView, OperationKind,
};
use sha2::{Digest, Sha256};

#[test]
fn core_pack_digest_is_pinned_and_carried_by_every_candidate() {
    let reference = core_pack_reference().expect("embedded pack verifies");
    let bytes = include_bytes!("../assets/identification/core-pack-v1.json");
    assert_eq!(
        reference.digest,
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    );
    assert_eq!(reference.id, "registrystack.relay.identification.core");
    assert_eq!(reference.version, "1");

    let report = identify_contract(&contract(), &[observed(false)]).expect("identifies");
    assert!(report
        .candidates
        .iter()
        .all(|candidate| candidate.rule_pack == reference));
}

#[test]
fn report_bytes_are_deterministic_across_observation_order() {
    let first = identify_contract(&contract(), &[observed(false)]).expect("first report");
    let second = identify_contract(&contract(), &[observed(true)]).expect("second report");
    assert_eq!(
        render_identification_report(&first).expect("first bytes"),
        render_identification_report(&second).expect("second bytes")
    );
    assert_eq!(
        identification_report_digest(&first).expect("first digest"),
        identification_report_digest(&second).expect("second digest")
    );
}

#[test]
fn technical_families_use_schema_and_authored_roles_only() {
    let report = identify_contract(&contract(), &[observed(false)]).expect("identifies");
    assert_candidate(
        &report,
        "id",
        CategoricalConfidence::Exact,
        IdentificationStatus::Suggested,
        Some(TechnicalRole::RecordIdentifier),
    );
    assert_candidate(
        &report,
        "revision",
        CategoricalConfidence::Exact,
        IdentificationStatus::Suggested,
        Some(TechnicalRole::RevisionIdentifier),
    );
    assert_candidate(
        &report,
        "status",
        CategoricalConfidence::Exact,
        IdentificationStatus::Suggested,
        Some(TechnicalRole::LifecycleState),
    );
    assert_candidate(
        &report,
        "recorded_at",
        CategoricalConfidence::Exact,
        IdentificationStatus::Suggested,
        Some(TechnicalRole::RecordedTime),
    );
    assert_candidate(
        &report,
        "region_code",
        CategoricalConfidence::Strong,
        IdentificationStatus::Suggested,
        Some(TechnicalRole::GeographicCode),
    );
    assert_candidate(
        &report,
        "category_code",
        CategoricalConfidence::Exact,
        IdentificationStatus::Suggested,
        Some(TechnicalRole::Codelist),
    );
    assert_candidate(
        &report,
        "person_reference",
        CategoricalConfidence::Strong,
        IdentificationStatus::Suggested,
        Some(TechnicalRole::PersonReference),
    );
    assert_candidate(
        &report,
        "notes",
        CategoricalConfidence::Weak,
        IdentificationStatus::Suggested,
        Some(TechnicalRole::Property),
    );
}

#[test]
fn generic_fallback_applies_only_when_no_specific_rule_matches() {
    let report = identify_contract(&contract(), &[observed(false)]).expect("identifies");
    let identified = report
        .candidates
        .iter()
        .find(|candidate| candidate.source_column == "id")
        .expect("identified candidate");
    assert!(identified
        .matched_rules
        .iter()
        .any(|rule| rule.id == "core.role.record-identifier"));
    assert!(!identified
        .matched_rules
        .iter()
        .any(|rule| rule.id == "core.column.fallback"));

    let fallback = report
        .candidates
        .iter()
        .find(|candidate| candidate.source_column == "notes")
        .expect("fallback candidate");
    assert_eq!(fallback.matched_rules.len(), 1);
    assert_eq!(fallback.matched_rules[0].id, "core.column.fallback");
    assert_eq!(fallback.suggested_role, Some(TechnicalRole::Property));

    let weak_specific = report
        .candidates
        .iter()
        .find(|candidate| candidate.source_column == "email_phone")
        .expect("weak specific candidate");
    assert!(weak_specific
        .matched_rules
        .iter()
        .all(|rule| rule.id != "core.column.fallback"));
}

#[test]
fn privacy_suggestions_are_explicitly_local_candidates_not_configured_scheme_terms() {
    let report = identify_contract(&contract(), &[observed(false)]).expect("identifies");
    assert_eq!(
        report.privacy_candidate_vocabulary.scheme,
        "urn:registrystack:relay:privacy-candidate"
    );
    assert_eq!(report.privacy_candidate_vocabulary.version, "1");

    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.source_column == "person_reference")
        .expect("privacy candidate");
    assert!(!candidate.suggested_privacy.is_empty());
    assert!(candidate.suggested_privacy.iter().all(|term| {
        term.scheme == report.privacy_candidate_vocabulary.scheme
            && term.version == report.privacy_candidate_vocabulary.version
            && term.scheme != "urn:example:privacy"
    }));
    assert!(candidate
        .suggested_privacy
        .iter()
        .any(|term| term.term == "identifying"));
}

#[test]
fn credible_name_rules_conflict_without_selecting_a_winner() {
    let report = identify_contract(&contract(), &[observed(false)]).expect("identifies");
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.source_column == "email_phone")
        .expect("candidate");
    assert_eq!(candidate.confidence, CategoricalConfidence::Conflict);
    assert_eq!(candidate.status, IdentificationStatus::Uncertain);
    assert_eq!(candidate.suggested_role, None);
    assert!(candidate
        .matched_rules
        .iter()
        .any(|rule| rule.id == "core.name.email-token" && rule.version == "1"));
    assert!(candidate
        .matched_rules
        .iter()
        .any(|rule| rule.id == "core.name.telephone-token" && rule.version == "1"));
    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(
        report.diagnostics[0].code,
        "identification.candidate_conflict"
    );
}

#[test]
fn source_row_value_canary_cannot_reach_report_or_diagnostics() {
    // The identification API has no row-value argument. This value represents
    // a row held by the source runtime and stays outside the observation.
    let source_row_value = "ROW_VALUE_CANARY_4f310b7235";
    let report = identify_contract(&contract(), &[observed(false)]).expect("identifies");
    let bytes = render_identification_report(&report).expect("report bytes");
    let rendered = String::from_utf8(bytes).expect("JSON is UTF-8");
    assert!(!rendered.contains(source_row_value));
    assert!(report
        .diagnostics
        .iter()
        .all(|diagnostic| !diagnostic.message.contains(source_row_value)));

    let value: serde_json::Value = serde_json::from_str(&rendered).expect("report JSON");
    assert_report_has_no_row_payload_fields(&value);
}

#[test]
fn generated_starter_is_unreviewed_and_binds_recomputed_report_and_pack() {
    let contract = contract();
    let observation = observed(false);
    let report =
        identify_contract(&contract, std::slice::from_ref(&observation)).expect("identifies");
    let registry = compile_contract(&contract, &[observation], CompileProfile::Authoring)
        .expect("contract compiles");
    let inventory_digest = classification_inventory_digest(&registry).expect("inventory digest");
    let starter = classification_review_starter(&contract, &inventory_digest, &report)
        .expect("starter renders");
    let generated = starter
        .generated_identification
        .clone()
        .expect("generated binding");
    assert_eq!(generated.report_ref, REVIEWED_IDENTIFICATION_REPORT_PATH);
    assert_eq!(
        generated.report_digest,
        identification_report_digest(&report).expect("report digest")
    );
    assert_eq!(generated.rule_pack, core_pack_reference().expect("pack"));
    assert_eq!(
        render_classification_review_yaml(&starter).expect("first starter bytes"),
        render_classification_review_yaml(&starter).expect("second starter bytes")
    );

    let validation = validate_classification_review(
        &starter,
        &ClassificationReviewExpectation {
            registry_identifier: contract.registry.registry_identifier.clone(),
            classification_inventory_digest: inventory_digest,
            generated_identification: Some(generated),
        },
    );
    assert!(!validation.is_valid());
    assert!(validation
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "classification.review_unreviewed"));
}

#[test]
fn generated_review_refuses_stale_inventory_report_and_pack_bindings() {
    let contract = contract();
    let report = identify_contract(&contract, &[observed(false)]).expect("identifies");
    let mut review = reviewed_generated(&contract, &report, digest('a'));
    let current = review
        .generated_identification
        .clone()
        .expect("generated binding");
    assert!(validate_classification_review(
        &review,
        &ClassificationReviewExpectation {
            registry_identifier: contract.registry.registry_identifier.clone(),
            classification_inventory_digest: digest('a'),
            generated_identification: Some(current.clone()),
        },
    )
    .is_valid());
    let stale_inventory = validate_classification_review(
        &review,
        &ClassificationReviewExpectation {
            registry_identifier: contract.registry.registry_identifier.clone(),
            classification_inventory_digest: digest('b'),
            generated_identification: Some(current.clone()),
        },
    );
    assert!(stale_inventory
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "classification.review_inventory_stale"));

    let mut expected_report = current.clone();
    expected_report.report_digest = digest('c');
    let stale_report = validate_classification_review(
        &review,
        &ClassificationReviewExpectation {
            registry_identifier: contract.registry.registry_identifier.clone(),
            classification_inventory_digest: digest('a'),
            generated_identification: Some(expected_report),
        },
    );
    assert!(stale_report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "classification.review_identification_stale"));

    review
        .generated_identification
        .as_mut()
        .expect("generated")
        .rule_pack
        .digest = digest('d');
    let stale_pack = validate_classification_review(
        &review,
        &ClassificationReviewExpectation {
            registry_identifier: contract.registry.registry_identifier.clone(),
            classification_inventory_digest: digest('a'),
            generated_identification: Some(current),
        },
    );
    assert!(stale_pack
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "classification.review_identification_stale"));
}

#[test]
fn manual_and_imported_reviews_are_first_class_and_forbid_generated_evidence() {
    let contract = contract();
    let report = identify_contract(&contract, &[observed(false)]).expect("identifies");
    let current_generated = GeneratedIdentificationBinding {
        report_ref: REVIEWED_IDENTIFICATION_REPORT_PATH.into(),
        report_digest: identification_report_digest(&report).expect("digest"),
        rule_pack: core_pack_reference().expect("pack"),
    };
    let expected = ClassificationReviewExpectation {
        registry_identifier: contract.registry.registry_identifier.clone(),
        classification_inventory_digest: digest('a'),
        generated_identification: Some(current_generated.clone()),
    };
    for method in [IdentificationMethod::Manual, IdentificationMethod::Imported] {
        let review = ClassificationReviewDocument {
            api_version: "relay.registrystack.org/classification-review/v1".into(),
            kind: "ClassificationReview".into(),
            registry_identifier: contract.registry.registry_identifier.clone(),
            classification_inventory_digest: digest('a'),
            method,
            reviewer: "urn:example:reviewer".into(),
            review_date: "2026-08-10".into(),
            status: ReviewStatus::Reviewed,
            rationale_ref: "governance/classification-rationale.yaml".into(),
            generated_identification: None,
        };
        assert!(validate_classification_review(&review, &expected).is_valid());

        let bytes = render_classification_review_yaml(&review).expect("YAML renders");
        assert_eq!(
            parse_classification_review_yaml(&bytes).expect("YAML parses"),
            review
        );
    }

    let invalid = ClassificationReviewDocument {
        api_version: "relay.registrystack.org/classification-review/v1".into(),
        kind: "ClassificationReview".into(),
        registry_identifier: contract.registry.registry_identifier.clone(),
        classification_inventory_digest: digest('a'),
        method: IdentificationMethod::Manual,
        reviewer: "urn:example:reviewer".into(),
        review_date: "2026-08-10".into(),
        status: ReviewStatus::Reviewed,
        rationale_ref: "governance/classification-rationale.yaml".into(),
        generated_identification: Some(current_generated),
    };
    let validation = validate_classification_review(&invalid, &expected);
    assert!(validation.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "classification.review_generated_binding_forbidden"
    }));
}

#[test]
fn embedded_pack_and_fixed_diagnostics_remain_source_neutral() {
    let pack =
        String::from_utf8_lossy(include_bytes!("../assets/identification/core-pack-v1.json"));
    for term in [
        "health",
        "medical",
        "civil-registration",
        "social-protection",
        "business-registry",
        "jurisdiction",
    ] {
        assert!(!pack.contains(term), "pack contains domain term {term}");
    }
}

#[test]
fn review_reports_are_canonical_value_free_and_cover_all_contextual_prompts() {
    let contract = contract();
    let observation = observed(false);
    let mut registry = compile_contract(&contract, &[observation], CompileProfile::Authoring)
        .expect("authoring contract compiles");
    let resource = &mut registry.resources[0];
    let person = resource
        .properties
        .iter_mut()
        .find(|property| property.name == "personReference")
        .expect("person property");
    person.classification.privacy = "identifying".into();
    person.classification.institutional = "public".into();
    person.classification.handling = registry_relay_v2::contract::Handling::Restricted;
    let contact = resource
        .properties
        .iter_mut()
        .find(|property| property.name == "emailPhone")
        .expect("contact property");
    contact.classification.privacy = "sensitive-personal".into();
    contact.classification.institutional = "public".into();
    contact.classification.handling = registry_relay_v2::contract::Handling::Confidential;
    for property_name in ["regionCode", "categoryCode"] {
        resource
            .properties
            .iter_mut()
            .find(|property| property.name == property_name)
            .expect("linkable property")
            .classification
            .privacy = "potentially-linkable".into();
    }
    let notes = resource
        .properties
        .iter_mut()
        .find(|property| property.name == "notes")
        .expect("notes property");
    let registry_relay_v2::model::CompiledPropertyBinding::Scalar(binding) = &mut notes.binding
    else {
        panic!("notes is scalar");
    };
    binding.transform = Some(CompiledTransform::PartialString {
        identifier: "partial-string:suffix:4".into(),
        reveal: PartialStringReveal::Suffix,
        characters: 4,
    });
    notes.classification.handling = registry_relay_v2::contract::Handling::Confidential;
    let mut masked_notes = notes.clone();
    masked_notes.name = "maskedNotes".into();
    masked_notes.classification.privacy = "partially-revealed-identifying".into();
    masked_notes.classification.handling = registry_relay_v2::contract::Handling::Internal;
    resource.properties.push(masked_notes);
    for column in &mut resource.column_accounting {
        if matches!(column.column.as_str(), "notes" | "region_code") {
            column.classification.handling = registry_relay_v2::contract::Handling::Restricted;
        }
    }
    let operation = &mut resource.operations[0];
    operation.kind = OperationKind::List;
    operation.query.selectors.push(CompiledSelector {
        name: "region".into(),
        source_column: "region_code".into(),
        data_type: DataType::String,
        minimum_bytes: None,
        maximum_bytes: Some(32),
        codelist: None,
    });
    operation.access_profiles[0].disclosure_handling =
        registry_relay_v2::contract::Handling::Confidential;
    operation.access_profiles[0].processing_handling =
        registry_relay_v2::contract::Handling::Restricted;

    let inventory_digest = classification_inventory_digest(&registry).expect("inventory digest");
    assert_eq!(
        classification_inventory_report(&registry, &digest('a')),
        Err(IdentificationError::InventoryDigestInvalid)
    );
    let inventory =
        classification_inventory_report(&registry, &inventory_digest).expect("inventory");
    let access_profiles =
        access_profile_report(&registry, &inventory_digest).expect("access profiles");
    let findings = contextual_review_findings(&registry, &inventory_digest).expect("findings");
    assert_eq!(inventory.classification_inventory_digest, inventory_digest);
    assert_eq!(access_profiles.kind, "AccessProfileReport");
    assert_eq!(
        access_profiles.classification_inventory_digest,
        inventory_digest
    );
    assert_eq!(findings.classification_inventory_digest, inventory_digest);
    assert_eq!(inventory.resources[0].source_columns.len(), 9);
    assert_eq!(inventory.resources[0].properties.len(), 6);
    let boundary = &access_profiles.resources[0].operations[0].access_profiles[0];
    assert!(boundary
        .processed_source_columns
        .contains(&"region_code".into()));
    assert!(boundary.disclosed_properties.contains(&"notes".into()));
    let codes = findings
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for expected in [
        "classification.context.identifying_and_sensitive",
        "classification.context.potentially_linkable_combination",
        "classification.context.personal_institutionally_public",
        "classification.context.selector_more_restrictive_than_disclosure",
        "classification.context.transform_weaker_than_source",
        "classification.context.nonpublic_list_disclosure",
        "classification.context.public_processes_hidden_nonpublic",
        "classification.context.source_column_incompatible_properties",
    ] {
        assert!(codes.contains(expected), "missing finding {expected}");
    }

    assert_eq!(
        render_classification_inventory_report(&inventory).expect("inventory bytes"),
        render_classification_inventory_report(&inventory).expect("inventory bytes again")
    );
    assert_eq!(
        render_access_profile_report(&access_profiles).expect("access profile bytes"),
        render_access_profile_report(&access_profiles).expect("access profile bytes again")
    );
    let finding_bytes = render_contextual_review_findings(&findings).expect("finding bytes");
    assert_eq!(
        finding_bytes,
        render_contextual_review_findings(&findings).expect("finding bytes again")
    );
    assert!(!String::from_utf8(finding_bytes)
        .expect("JSON")
        .contains("ROW_VALUE_CANARY"));
}

fn assert_candidate(
    report: &registry_relay_v2::identification::IdentificationReport,
    column: &str,
    confidence: CategoricalConfidence,
    status: IdentificationStatus,
    role: Option<TechnicalRole>,
) {
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.source_column == column)
        .unwrap_or_else(|| panic!("missing candidate for {column}"));
    assert_eq!(candidate.confidence, confidence, "{column}");
    assert_eq!(candidate.status, status, "{column}");
    assert_eq!(candidate.suggested_role, role, "{column}");
}

fn assert_report_has_no_row_payload_fields(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for row_derived_field in [
                "sample",
                "samples",
                "sampleValue",
                "sampleValues",
                "row",
                "rows",
                "value",
                "values",
            ] {
                assert!(
                    !object.contains_key(row_derived_field),
                    "report exposes row-derived field {row_derived_field}"
                );
            }
            object
                .values()
                .for_each(assert_report_has_no_row_payload_fields);
        }
        serde_json::Value::Array(values) => {
            values
                .iter()
                .for_each(assert_report_has_no_row_payload_fields);
        }
        _ => {}
    }
}

fn reviewed_generated(
    contract: &RegistryContract,
    report: &registry_relay_v2::identification::IdentificationReport,
    inventory_digest: String,
) -> ClassificationReviewDocument {
    let mut review =
        classification_review_starter(contract, &inventory_digest, report).expect("starter builds");
    review.review_date = "2026-08-10".into();
    review.status = ReviewStatus::Reviewed;
    review.rationale_ref = "governance/classification-rationale.yaml".into();
    review
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn observed(reverse: bool) -> ObservedSourceSchema {
    let mut columns = [
        ("id", "TEXT", false, true),
        ("revision", "TEXT", false, false),
        ("status", "TEXT", false, false),
        ("recorded_at", "TEXT", false, false),
        ("region_code", "TEXT", true, false),
        ("category_code", "TEXT", true, false),
        ("person_reference", "TEXT", true, false),
        ("email_phone", "TEXT", true, false),
        ("notes", "TEXT", true, false),
    ]
    .into_iter()
    .map(
        |(name, declared_type, nullable, primary_key)| ObservedColumn {
            name: name.into(),
            declared_type: declared_type.into(),
            nullable,
            primary_key,
        },
    )
    .collect::<Vec<_>>();
    if reverse {
        columns.reverse();
    }
    ObservedSourceSchema {
        source: "registry".into(),
        fingerprint: digest('e'),
        views: vec![ObservedView {
            name: "records".into(),
            columns,
        }],
    }
}

fn contract() -> RegistryContract {
    RegistryContract::parse_yaml(
        r#"apiVersion: relay.registrystack.org/v2alpha1
kind: RegistryContract
metadata: {id: test, version: "1", title: Test}
registry:
  registryIdentifier: urn:example:registry:test
  name: Test
  authority: {identifier: urn:example:authority, name: Authority}
  authoritativeScope: Test records
  baseUri: https://registry.example.invalid/
  identifierLifecyclePolicyRef: governance/lifecycle.yaml
  alignmentTargets: [{name: test-profile, version: "1", status: directional}]
governance: {controller: urn:example:authority, publisher: urn:example:authority, auditOwner: urn:example:audit}
semantics: {localVocabulary: https://registry.example.invalid/vocabulary/}
classifications:
  privacy: {scheme: urn:example:privacy, version: "1"}
  institutional: {scheme: urn:example:institutional, version: "1"}
  handling: {scheme: urn:example:handling, version: "1"}
  provenanceRef: governance/classification-review.yaml
sources:
  registry: {kind: sqlite, profile: snapshot, expectedSchemaFingerprint: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
resources:
  - id: records
    datasetIdentifier: records
    entityTypeIdentifier: record
    title: Records
    description: Records
    semanticClass: local:Record
    source: {source: registry, view: records}
    classificationDefaults: {privacy: unknown, institutional: public, handling: public, status: suggested}
    recordContext:
      recordIdentifier: {sourceColumn: id}
      revisionIdentifier: {sourceColumn: revision}
      lifecycleState: {sourceColumn: status, codelist: codelists/status.yaml}
      recordedAt: {sourceColumn: recorded_at}
    sourceColumnClassifications: {}
    properties:
      regionCode: {label: Region code, description: Region code, sourceColumn: region_code, type: string, sourceRequired: false, semanticTerm: "local:regionCode"}
      categoryCode: {label: Category code, description: Category code, sourceColumn: category_code, type: controlled-code, codelist: codelists/category.yaml, sourceRequired: false, semanticTerm: "local:categoryCode"}
      personReference: {label: Person reference, description: Person reference, sourceColumn: person_reference, type: string, sourceRequired: false, semanticTerm: "local:personReference"}
      emailPhone: {label: Contact, description: Contact, sourceColumn: email_phone, type: string, sourceRequired: false, semanticTerm: "local:contact"}
      notes: {label: Notes, description: Notes, sourceColumn: notes, type: string, sourceRequired: false, semanticTerm: "local:notes"}
    disclosureProfiles: {default: {properties: [regionCode, categoryCode, personReference, emailPhone, notes]}}
    operations:
      read:
        defaultAccessProfile: default
        accessProfiles:
          default: {access: public, disclosureProfile: default}
    processingDescriptions: []
metadataVisibility: {service: public, resources: public, semantics: public, classifications: operator-only, processing: operation-bound}
"#,
    )
    .expect("test contract parses")
}
