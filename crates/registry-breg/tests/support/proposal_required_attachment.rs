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
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
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
