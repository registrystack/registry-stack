// SPDX-License-Identifier: Apache-2.0

#[test]
fn claim_scopes_are_enforced_by_notary() {
    let mut claim = test_claim("selected", Vec::new(), false);
    claim.required_scopes = vec!["registry:consult:dhis2".to_string()];
    let denied = machine_principal();

    assert!(!principal_can_see_claim(&denied, &claim));
    assert!(matches!(
        require_claim_access(&denied, &claim),
        Err(EvidenceError::ScopeDenied { required })
            if required == "registry:consult:dhis2"
    ));

    let mut allowed = denied;
    allowed.scopes.push("registry:consult:dhis2".to_string());
    assert!(principal_can_see_claim(&allowed, &claim));
    require_claim_access(&allowed, &claim).expect("claim scope grants access");
}

#[tokio::test]
async fn batch_subject_purpose_conflict_rejects_batch_default() {
    let mut claim = test_claim("selected", Vec::new(), true);
    claim.operations.batch_evaluate.enabled = true;
    claim.operations.batch_evaluate.max_subjects = 2;
    let mut evidence_config = (*test_evidence(vec![claim])).clone();
    evidence_config.inline_batch_limit = 2;
    let evidence = Arc::new(evidence_config);
    let store = EvidenceStore::default();
    let request = BatchEvaluateRequest {
        items: vec![
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                    purpose: Some("program-a".to_string()),
                },
            ),
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-2".to_string(),
                    id_type: None,
                    purpose: None,
                },
            ),
        ],
        claims: vec![ClaimRef::from("selected")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("program-b".to_string()),
    };

    let error = RegistryNotaryRuntime::new()
        .batch_evaluate(
            evidence,
            &store,
            &machine_principal(),
            request,
            BatchEvaluateOptions::default(),
        )
        .await
        .expect_err("batch item purpose must not conflict with batch default");

    assert_eq!(error.code(), "request.invalid");
}
