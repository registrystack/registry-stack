// SPDX-License-Identifier: Apache-2.0

fn test_claim(id: &str, depends_on: Vec<&str>, _has_source: bool) -> ClaimDefinition {
    ClaimDefinition {
        id: id.to_string(),
        title: id.to_string(),
        version: "1.0".to_string(),
        subject_type: "person".to_string(),
        evidence_mode: ClaimEvidenceMode::SelfAttested,
        value: registry_notary_core::ClaimValueConfig {
            value_type: "boolean".to_string(),
            nullable: false,
            unit: None,
        },
        semantics: None,
        inputs: Vec::new(),
        depends_on: depends_on.into_iter().map(str::to_string).collect(),
        purpose: None,
        required_scopes: Vec::new(),
        rule: RuleConfig::ConsultationMatched {
            consultation: "src".to_string(),
        },
        operations: registry_notary_core::ClaimOperationsConfig::default(),
        disclosure: registry_notary_core::DisclosureConfig {
            default: "value".to_string(),
            allowed: vec!["value".to_string(), "redacted".to_string()],
            downgrade: "redacted".to_string(),
        },
        formats: vec![FORMAT_CLAIM_RESULT_JSON.to_string()],
        credential_profiles: Vec::new(),
        cccev: None,
        oots: None,
    }
}

fn test_evidence(claims: Vec<ClaimDefinition>) -> Arc<EvidenceConfig> {
    Arc::new(EvidenceConfig {
        enabled: true,
        service_id: "runtime.test".to_string(),
        claims,
        ..EvidenceConfig::default()
    })
}

fn test_claim_result(
    claim_id: &str,
    value: Value,
    redaction_fields: BTreeSet<String>,
) -> ClaimResultInternal {
    ClaimResultInternal {
        evaluation_id: "eval-test".to_string(),
        claim_id: claim_id.to_string(),
        claim_version: "1.0".to_string(),
        subject_type: "person".to_string(),
        target: EvidenceEntity::new("Person"),
        requester: None,
        value,
        redaction_fields,
        issued_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: None,
        provenance: ClaimProvenance::new(
            "runtime.test".to_string(),
            "eval-test".to_string(),
            claim_id.to_string(),
            "1.0".to_string(),
            ProvenanceUsed {
                relay_consultation_count: 0,
            },
        ),
        relay_consultation_ids: BTreeSet::new(),
    }
}

fn test_request(claim: &str) -> EvaluateRequest {
    EvaluateRequest {
        requester: None,
        target: Some(EvidenceEntity::from_subject_request(
            "Person",
            SubjectRequest {
                id: "person-1".to_string(),
                id_type: None,
            },
        )),
        relationship: None,
        on_behalf_of: None,
        variables: Default::default(),
        claims: vec![ClaimRef::from(claim)],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    }
}

fn machine_principal() -> EvidencePrincipal {
    EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
        principal_id: "machine".to_string(),
        scopes: Vec::new(),
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    }
}

fn subject_access_principal() -> EvidencePrincipal {
    EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::ExternalOidc,
        principal_id: "citizen".to_string(),
        scopes: vec!["subject_access".to_string()],
        access_mode: AccessMode::SubjectBound,
        verified_claims: None,
        authorization_details: None,
    }
}

fn delegated_attestation_capability(
    keys: &SubjectAccessRateLimitKeys,
    requester_subject: &str,
    dependent_subject: &str,
) -> EvaluationCapability {
    EvaluationCapability::DelegatedAttestation {
        proof_claim_id: BoundedClaimId::new("guardian-link").expect("proof claim id is bounded"),
        allowed_claim_ids: BTreeSet::from([
            BoundedClaimId::new("selected").expect("delegated claim id is bounded"),
        ]),
        requester_subject_binding_hash: keys
            .delegated_subject_binding("national_id", requester_subject)
            .expect("requester hashes"),
        dependent_target_hash: keys
            .delegated_subject_binding("civil_registration_id", dependent_subject)
            .expect("dependent hashes"),
        relationship_type: registry_notary_core::ConfigMetadata::new("guardian")
            .expect("relationship type is bounded"),
    }
}

fn delegated_principal() -> EvidencePrincipal {
    EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::ExternalOidc,
        principal_id: "guardian".to_string(),
        scopes: Vec::new(),
        access_mode: AccessMode::DelegatedAttestation,
        verified_claims: None,
        authorization_details: None,
    }
}

fn delegated_runtime_request() -> EvaluateRequest {
    EvaluateRequest {
        requester: Some(EvidenceEntity::from_subject_request(
            "Person",
            SubjectRequest {
                id: "NAT-123".to_string(),
                id_type: Some("national_id".to_string()),
            },
        )),
        target: Some(EvidenceEntity::from_subject_request(
            "Person",
            SubjectRequest {
                id: "CHILD-123".to_string(),
                id_type: Some("civil_registration_id".to_string()),
            },
        )),
        relationship: Some(registry_notary_core::EvidenceRelationship {
            relationship_type: "guardian".to_string(),
            attributes: BTreeMap::new(),
        }),
        on_behalf_of: None,
        variables: Default::default(),
        claims: vec![ClaimRef::from("selected")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    }
}
