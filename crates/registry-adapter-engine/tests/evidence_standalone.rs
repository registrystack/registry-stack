//! The maintained standalone example executes its reviewed pack through sealed replay.
use registry_adapter_core::AdapterPack;
use registry_adapter_engine::{
    artifacts::PackArtifactBytes,
    evidence::{
        compile_evidence_pack, EvidenceAcquisitionIntent, EvidenceHookFuture, EvidenceHostHooks,
        EvidenceLimits, EvidenceLookup,
    },
    replay::ReplayTranscript,
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf, sync::Arc};

struct Hooks;
impl EvidenceHostHooks for Hooks {
    fn before_acquisition<'a>(
        &'a self,
        _intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

async fn lookup(route: &str, path: &str, response: Value) -> Result<EvidenceLookup, String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/examples/standalone/adapter-packs/synthetic-register");
    let mut value: Value =
        serde_json::from_slice(&fs::read(root.join("pack.yaml")).expect("maintained pack exists"))
            .expect("JSON is valid YAML");
    let object = value.as_object_mut().unwrap();
    assert_eq!(
        object.remove("apiVersion"),
        Some(json!("id.registrystack.org/formats/adapter/pack/v1alpha1"))
    );
    assert_eq!(object.remove("kind"), Some(json!("AdapterPack")));
    let pack: AdapterPack = serde_json::from_value(value).expect("reviewed pack grammar");
    let artifacts = PackArtifactBytes::new(
        [
            "schemas/inputs.json",
            "schemas/person.json",
            "schemas/licence.json",
            "schemas/parents.json",
            "scripts/lookup.rhai",
        ]
        .into_iter()
        .map(|path| (path.to_owned(), fs::read(root.join(path)).unwrap())),
    );
    let checked = compile_evidence_pack(&pack, route, &artifacts, EvidenceLimits::default())
        .expect("pure source compile");
    let transcript = Arc::new(ReplayTranscript::from_exchanges(
        serde_json::from_value(json!([{"type":"endpoint","endpoint":"register"}])).unwrap(),
        serde_json::from_value(json!([{"request":{"endpoint":"register","method":"GET","path":path},"response":{"status":200,"body":response}}])).unwrap(),
    ));
    let program = checked.bind_replay(Arc::clone(&transcript)).unwrap();
    let acquisition = program.begin_acquisition(Arc::new(Hooks)).await.unwrap();
    let result = program
        .execute(&acquisition, json!({"recordId":"0007"}))
        .await
        .map_err(|_| "source-protocol".to_owned());
    transcript
        .finish()
        .expect("actual route consumed the exact recorded request");
    result
}

#[tokio::test]
async fn standalone_provider_preserves_match_absence_ambiguity_and_identity_refusal() {
    let record = json!({"record_id":"0007","birth_date":"1980-01-01","residence_region":"north","address_canary":"private-canary"});
    assert_eq!(
        lookup("person", "/people/0007", json!({"total":1,"record":record}))
            .await
            .unwrap(),
        EvidenceLookup::Matched {
            facts: json!({"birth-date":"1980-01-01","residence-region":"north","address-canary":"private-canary"})
        }
    );
    assert_eq!(
        lookup("person", "/people/0007", json!({"total":0}))
            .await
            .unwrap(),
        EvidenceLookup::NoMatch
    );
    assert_eq!(
        lookup("person", "/people/0007", json!({"total":2}))
            .await
            .unwrap(),
        EvidenceLookup::Ambiguous
    );
    let mut wrong = record.clone();
    wrong["record_id"] = json!("someone-else");
    assert!(
        lookup("person", "/people/0007", json!({"total":1,"record":wrong}))
            .await
            .is_err()
    );
    let mut invalid = record;
    invalid["birth_date"] = json!("2026-02-31");
    assert!(lookup(
        "person",
        "/people/0007",
        json!({"total":1,"record":invalid})
    )
    .await
    .is_err());
}

#[tokio::test]
async fn standalone_parent_source_requires_a_complete_unique_bounded_set() {
    assert_eq!(lookup("parents", "/parents/0007", json!({"total":1,"record":{"record_id":"0007","complete":true,"parents":["parent-a","parent-b"]}})).await.unwrap(), EvidenceLookup::Matched {facts:json!({"parents":["parent-a","parent-b"]})});
    for record in [
        json!({"record_id":"0007","complete":false,"parents":[]}),
        json!({"record_id":"0007","complete":true,"parents":["parent-a","parent-a"]}),
    ] {
        assert!(lookup(
            "parents",
            "/parents/0007",
            json!({"total":1,"record":record})
        )
        .await
        .is_err());
    }
}
