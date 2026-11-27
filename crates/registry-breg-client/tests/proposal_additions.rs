// SPDX-License-Identifier: Apache-2.0
use registry_breg_client::BRegProposal;
use serde_json::{json, Value};

fn proposal() -> Value {
    let id = "00000000-0000-4000-8000-000000000001";
    let addition = "00000000-0000-4000-8000-000000000002";
    json!({"id":id,"actionId":"correct","actionRevision":format!("sha256:{}","a".repeat(64)),
        "submissionVersion":1,"revision":3,"state":"submitted","turn":"official",
        "effectDigest":format!("sha256:{}","b".repeat(64)),"links":{},
        "additions":{"other":{"id":"other","maximumBytes":32,"maximumCount":2,
            "contentTypes":["text/plain"],"classification":"restricted","links":{
                "add":{"method":"POST","path":format!("/v1/proposals/{id}/additions/other"),
                    "accessProfile":"writer","operation":"add","ifMatch":"\"breg-proposal-three\"",
                    "availability":{"available":true,"observedRevision":3}}},
            "items":[{"id":addition,"submissionVersion":1,"sha256":"a".repeat(64),"byteSize":4,
                "contentType":"text/plain","addedAt":"2026-11-27T00:00:00Z","verificationStatus":"notRequired",
                "links":{"download":{"method":"GET","path":format!("/v1/proposals/{id}/additions/{addition}?submissionVersion=1"),
                    "accessProfile":"writer","operation":"download","availability":{"available":true,"observedRevision":3}}}}]}}})
}

#[test]
fn additions_decode_and_keep_the_limit_reason_closed() {
    let source = proposal();
    BRegProposal::from_slice(&serde_json::to_vec(&source).unwrap()).expect("additions decode");
    let mut full = source;
    full["additions"]["other"]["links"]["add"]["availability"] = json!({
        "available":false,"observedRevision":3,"reason":"limit-reached","recovery":"receipt-only"});
    BRegProposal::from_slice(&serde_json::to_vec(&full).unwrap()).expect("limit reason decodes");
    full["additions"]["other"]["links"]["add"]["availability"]["reason"] = json!("unknown-reason");
    assert!(BRegProposal::from_slice(&serde_json::to_vec(&full).unwrap()).is_err());
}

#[test]
fn additions_retain_files_when_the_current_count_limit_is_lowered() {
    let mut source = proposal();
    let slot = &mut source["additions"]["other"];
    slot["maximumCount"] = json!(1);
    let mut second = slot["items"][0].clone();
    second["id"] = json!("00000000-0000-4000-8000-000000000003");
    second["links"] = json!({});
    slot["items"].as_array_mut().unwrap().push(second);
    slot["links"]["add"]["availability"] = json!({
        "available":false,"observedRevision":3,"reason":"limit-reached","recovery":"receipt-only"});
    let decoded = BRegProposal::from_slice(&serde_json::to_vec(&source).unwrap())
        .expect("a lower current limit must not hide retained files");
    assert_eq!(decoded.addition_slot("other").unwrap().items().len(), 2);
}

#[test]
fn additions_refuse_wrong_paths_versions_bounds_and_unknown_members() {
    for mutation in 0..7 {
        let mut source = proposal();
        let slot = &mut source["additions"]["other"];
        match mutation {
            0 => slot["maximumCount"] = json!(33),
            1 => slot["items"][0]["submissionVersion"] = json!(2),
            2 => {
                slot["items"][0]["links"]["download"]["path"] =
                    json!("https://untrusted.example.test/file")
            }
            3 => slot["links"]["add"]["method"] = json!("PATCH"),
            4 => slot["items"][0]["addedAt"] = json!("tomorrow"),
            5 => slot["items"][0]["fileName"] = json!("private-name"),
            _ => {
                slot["links"]["add"]["path"] =
                    json!("/v1/proposals/00000000-0000-4000-8000-000000000099/additions/other")
            }
        }
        assert!(
            BRegProposal::from_slice(&serde_json::to_vec(&source).unwrap()).is_err(),
            "mutation {mutation}"
        );
    }
}
