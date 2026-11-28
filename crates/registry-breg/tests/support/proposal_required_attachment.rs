// SPDX-License-Identifier: Apache-2.0
use super::*;

async fn required_slot(readable: bool) {
    let mut source = registry_source(false);
    source["actions"]["correct-name"]["execution"]["proposal"]["attachments"][0]["required"] =
        json!(true);
    if !readable {
        source["accessProfiles"]["clerk"]["permissions"]["proposals"][0]["readableAttachments"] =
            json!([]);
    }
    let registry = if readable {
        registry_breg::compiler::compile_project(
            &registry_breg::contract::parse_project_yaml(include_bytes!(
                "../../../../products/breg/examples/required-attachment/registry.yaml"
            ))
            .unwrap(),
            &[],
            CompileProfile::Authoring,
        )
        .unwrap()
    } else {
        compile(source)
    };
    let fixture = client_http::ClientFixture::start(registry, claims("author", "zone-a")).await;
    let draft = start(&fixture, "Required file", "required-file-start").await;
    let value = serde_json::to_value(&draft).unwrap();
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/proposals/{}/submit?accessProfile=clerk",
            fixture.http.base_url,
            draft.id()
        ))
        .header(
            "if-match",
            value["links"]["submit"]["ifMatch"].as_str().unwrap(),
        )
        .header("idempotency-key", "required-file-missing")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let problem: Value = response.json().await.unwrap();
    assert_eq!(status, 422, "missing required file: {problem}");
    assert_eq!(problem["code"], "attachment.required");
    assert_eq!(problem["fieldPath"], "/attachments/support");
    assert_eq!(value["links"]["submit"]["availability"]["available"], false);
    assert_eq!(
        value["links"]["submit"]["availability"]["reason"],
        "attachment-required"
    );
    assert_eq!(
        value["links"]["submit"]["availability"]["recovery"],
        "correct-input"
    );
    let uploaded = fixture
        .http
        .client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"required support",
            &key("required-file-upload"),
        )
        .await
        .unwrap()
        .value;
    let current = fixture
        .http
        .client
        .read_proposal(&uploaded)
        .await
        .unwrap()
        .value;
    let value = serde_json::to_value(&current).unwrap();
    assert_eq!(value["links"]["submit"]["availability"]["available"], true);
    assert_eq!(
        value["attachments"]["support"].get("value").is_some(),
        readable
    );
    let client = &fixture.http.client;
    let submitted = client
        .execute_proposal(
            &client
                .prepare_proposal(&current, "submit", json!({}), &key("required-file-submit"))
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    fixture.finish().await;
}

#[tokio::test]
async fn submit_names_an_empty_required_attachment_and_recovers_after_upload() {
    required_slot(true).await;
}

#[tokio::test]
async fn submit_checks_required_attachments_the_writer_cannot_read() {
    required_slot(false).await;
}

async fn verified_slot(required: bool, verdict: &str, readable: bool) {
    use registry_breg::attachment_verification::AttachmentVerification;
    use registry_platform_config::{AttachmentVerifierConfig, SecretProvider, SecretResolver};
    use registry_platform_objectstore::{HttpVerifierSettings, VerifierNamespace};
    let secrets = tempfile::tempdir().unwrap();
    let credential = secrets.path().join("verifier");
    std::fs::write(&credential, b"synthetic-verifier-token").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let resolver = SecretResolver::new([SecretProvider::File], secrets.path()).unwrap();
    let config: AttachmentVerifierConfig = serde_json::from_value(json!({
        "url":"http://127.0.0.1:1/verify","policyId":"synthetic-policy",
        "authorizationRef":"secret:file/verifier","attemptTimeoutMilliseconds":2000
    }))
    .unwrap();
    let verification = AttachmentVerification::Http(std::sync::Arc::new(
        HttpVerifierSettings::from_config_without_peer_policy(&config)
            .unwrap()
            .activate(
                VerifierNamespace {
                    binding_domain: "breg-attachment-verification-http-v1",
                    max_content_bytes: registry_breg::contract::MAX_ATTACHMENT_BYTES as u64,
                },
                &resolver,
            )
            .unwrap(),
    ));
    let policy = verification.binding_digest();
    let mut source = registry_source(false);
    source["actions"]["correct-name"]["execution"]["proposal"]["attachments"][0]["required"] =
        json!(required);
    if !readable {
        source["accessProfiles"]["clerk"]["permissions"]["proposals"][0]["readableAttachments"] =
            json!([]);
    }
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| mutations.with_attachment_verification(verification),
    )
    .await;
    let draft = start(&fixture, "Verification", "verification-start").await;
    let uploaded = fixture
        .http
        .client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"synthetic supporting file",
            &key("verification-upload"),
        )
        .await
        .unwrap()
        .value;
    if verdict != "pending" {
        fixture.database.admin.execute(
            "INSERT INTO registry_internal.registry_attachment_verification (sha256,policy_digest,content_type,verdict)
             SELECT sha256,$1,content_type,$2 FROM registry_internal.registry_proposal_attachments WHERE slot_id='support'
             ON CONFLICT (sha256,policy_digest,content_type) DO UPDATE SET verdict=EXCLUDED.verdict",
            &[&policy,&verdict]).await.unwrap();
    }
    let current = reqwest::get(format!(
        "{}/v1/proposals/{}?accessProfile=clerk",
        fixture.http.base_url,
        uploaded.id()
    ))
    .await
    .unwrap();
    let etag = current.headers()["etag"].to_str().unwrap().to_owned();
    let current: Value = current.json().await.unwrap();
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/proposals/{}/submit?accessProfile=clerk",
            fixture.http.base_url,
            uploaded.id()
        ))
        .header("if-match", etag)
        .header("idempotency-key", "verification-submit")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let problem: Value = response.json().await.unwrap();
    let (expected_status, code, reason, recovery) = match (required, verdict) {
        (_, "pending") => (
            409,
            "attachment.verification-pending",
            "attachment-pending",
            "refresh",
        ),
        (true, "rejected") => (
            422,
            "attachment.required",
            "attachment-required",
            "correct-input",
        ),
        (false, "rejected") => (
            422,
            "attachment.verification-rejected",
            "invalid-input",
            "correct-input",
        ),
        _ => unreachable!(),
    };
    assert_eq!(
        current["links"]["submit"]["availability"],
        json!({
            "available":false,"observedRevision":current["revision"],"reason":reason,"recovery":recovery
        })
    );
    assert_eq!(status, expected_status, "{problem}");
    assert_eq!(problem["code"], code);
    assert_eq!(problem["fieldPath"], "/attachments/support");
    assert_eq!(
        problem
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(
            [
                "type",
                "title",
                "status",
                "detail",
                "code",
                "traceId",
                "fieldPath"
            ]
            .map(str::to_owned)
        )
    );
    if !readable {
        assert!(current["attachments"]["support"].get("value").is_none());
    }
    let client = &fixture.http.client;
    let ready = if verdict == "rejected" && !required {
        client
            .delete_proposal_attachment(&uploaded, "support", &key("verification-remove"))
            .await
            .unwrap()
            .value
    } else {
        let current = if verdict == "rejected" {
            client
                .upload_proposal_attachment(
                    &uploaded,
                    "support",
                    "text/plain",
                    b"replacement supporting file",
                    &key("verification-replace"),
                )
                .await
                .unwrap()
                .value
        } else {
            uploaded
        };
        // Model the verifier completing its verdict, without a network poll or clock delay.
        fixture.database.admin.execute(
            "UPDATE registry_internal.registry_attachment_verification SET verdict='approved' WHERE verdict='pending'",
            &[],
        ).await.unwrap();
        client.read_proposal(&current).await.unwrap().value
    };
    assert!(
        ready
            .link("submit")
            .unwrap()
            .availability()
            .unwrap()
            .available
    );
    let submitted = client
        .execute_proposal(
            &client
                .prepare_proposal(&ready, "submit", json!({}), &key("verification-submit"))
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    // A later verification observation cannot reopen the Submit lifecycle command.
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_verification SET verdict='pending'",
            &[],
        )
        .await
        .unwrap();
    let current = client.read_proposal(&submitted).await.unwrap().value;
    let current = serde_json::to_value(&current).unwrap();
    let wrong_state = reqwest::Client::new()
        .post(format!(
            "{}/v1/proposals/{}/submit?accessProfile=clerk",
            fixture.http.base_url,
            submitted.id()
        ))
        .header(
            "if-match",
            current["links"]["submit"]["ifMatch"].as_str().unwrap(),
        )
        .header("idempotency-key", "verification-submit-again")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_state.status(), 412);
    fixture.finish().await;
}

#[tokio::test]
async fn submit_and_link_agree_for_pending_verification() {
    for readable in [true, false] {
        verified_slot(true, "pending", readable).await;
    }
}

#[tokio::test]
async fn submit_and_link_treat_a_rejected_required_file_as_empty() {
    for readable in [true, false] {
        verified_slot(true, "rejected", readable).await;
    }
}

#[tokio::test]
async fn submit_and_link_name_a_rejected_optional_file_without_metadata() {
    for readable in [true, false] {
        verified_slot(false, "rejected", readable).await;
    }
}

#[tokio::test]
async fn required_file_precedes_plan_evaluation() {
    let mut source = registry_source(false);
    source["actions"]["correct-name"]["execution"]["proposal"]["attachments"][0]["required"] =
        json!(true);
    source["functions"] = json!({"failing-plan":{"runtime":"rhai","source":"plans/failing.rhai","entrypoint":"plan","abi":"registry.action-plan/v1"}});
    source["actions"]["correct-name"]["plan"] = json!({"type":"function","function":"failing-plan","inputs":["target","value"],
        "writes":[{"id":"name","target":{"fromInput":"target"},"operation":"patch","fields":["name"]}]});
    let registry = compile_project_with_assets(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/failing.rhai".into(),
            bytes: br#"fn plan(ctx) { throw "synthetic plan failure"; }"#.to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap();
    let fixture = client_http::ClientFixture::start(registry, claims("author", "zone-a")).await;
    let draft = start(&fixture, "Required before plan", "precedence-start").await;
    let value = serde_json::to_value(&draft).unwrap();
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/proposals/{}/submit?accessProfile=clerk",
            fixture.http.base_url,
            draft.id()
        ))
        .header(
            "if-match",
            value["links"]["submit"]["ifMatch"].as_str().unwrap(),
        )
        .header("idempotency-key", "precedence-submit")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    assert_eq!(
        response.json::<Value>().await.unwrap()["code"],
        "attachment.required"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn submit_without_slot_write_authority_names_the_first_empty_slot_only() {
    let mut source = registry_source(false);
    let mut alpha =
        source["actions"]["correct-name"]["execution"]["proposal"]["attachments"][0].clone();
    alpha["required"] = json!(true);
    alpha["id"] = json!("zeta");
    source["actions"]["correct-name"]["execution"]["proposal"]["attachments"]
        .as_array_mut()
        .unwrap()
        .push(alpha.clone());
    alpha["id"] = json!("alpha");
    source["actions"]["correct-name"]["execution"]["proposal"]["attachments"]
        .as_array_mut()
        .unwrap()
        .push(alpha);
    let grant = &mut source["accessProfiles"]["clerk"]["permissions"]["proposals"][0];
    grant["readableAttachments"] = json!([]);
    grant["writableAttachments"] = json!([]);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let draft = start(&fixture, "Split responsibilities", "split-start").await;
    let value = serde_json::to_value(&draft).unwrap();
    assert!(value.get("attachments").is_none());
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/proposals/{}/submit?accessProfile=clerk",
            fixture.http.base_url,
            draft.id()
        ))
        .header(
            "if-match",
            value["links"]["submit"]["ifMatch"].as_str().unwrap(),
        )
        .header("idempotency-key", "split-submit")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    let problem: Value = response.json().await.unwrap();
    assert_eq!(problem["fieldPath"], "/attachments/alpha");
    assert!(problem.get("fieldPaths").is_none());
    assert!(!problem.to_string().contains("zeta"));
    fixture.finish().await;
}

#[tokio::test]
async fn slot_upload_names_media_and_size_refusals() {
    let fixture =
        client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
    let draft = start(&fixture, "Upload refusals", "upload-refusal-start").await;
    let value = serde_json::to_value(&draft).unwrap();
    for (content_type, bytes, status, code) in [
        (
            "application/pdf",
            b"file".to_vec(),
            415,
            "attachment.content-type",
        ),
        ("text/plain", vec![b'x'; 4097], 413, "attachment.too-large"),
    ] {
        let response = reqwest::Client::new()
            .patch(format!(
                "{}/v1/proposals/{}/attachments/support?accessProfile=clerk",
                fixture.http.base_url,
                draft.id()
            ))
            .header(
                "if-match",
                value["links"]["edit"]["ifMatch"].as_str().unwrap(),
            )
            .header("idempotency-key", format!("upload-refusal-{status}"))
            .header("content-type", content_type)
            .body(bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.json::<Value>().await.unwrap()["code"], code);
    }
    fixture.finish().await;
}

#[tokio::test]
async fn a_retired_slot_reference_refuses_submit_without_concealing_the_proposal() {
    let fixture =
        client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
    let draft = start(&fixture, "Retired slot", "retired-slot-start").await;
    let uploaded = fixture
        .http
        .client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"support",
            &key("retired-slot-upload"),
        )
        .await
        .unwrap()
        .value;
    // Model a reference retained from a removed slot; current grants cannot name it.
    fixture.database.admin.execute(
        "INSERT INTO registry_internal.registry_proposal_attachments
            (action_id,proposal_id,submission_version,slot_id,sha256,content_type,byte_size,uploaded_at,uploaded_by)
         SELECT action_id,proposal_id,submission_version,'retired-slot',sha256,content_type,byte_size,uploaded_at,uploaded_by
         FROM registry_internal.registry_proposal_attachments WHERE slot_id='support'",
        &[],
    ).await.unwrap();
    let response = reqwest::get(format!(
        "{}/v1/proposals/{}?accessProfile=clerk",
        fixture.http.base_url,
        uploaded.id()
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    let current: Value = response.json().await.unwrap();
    assert_eq!(
        current["links"]["submit"]["availability"]["available"],
        false
    );
    assert!(!current.to_string().contains("retired-slot"));
    let refused = reqwest::Client::new()
        .post(format!(
            "{}/v1/proposals/{}/submit?accessProfile=clerk",
            fixture.http.base_url,
            uploaded.id()
        ))
        .header(
            "if-match",
            current["links"]["submit"]["ifMatch"].as_str().unwrap(),
        )
        .header("idempotency-key", "retired-slot-submit")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 412);
    let problem: Value = refused.json().await.unwrap();
    assert_eq!(problem["code"], "precondition.failed");
    assert!(problem.get("fieldPath").is_none());
    fixture.finish().await;
}
