//! The Evidence host installs only explicitly selected, pinned protocol implementations.
use registry_adapter_core::AdapterPack;
use registry_adapter_engine::{
    artifacts::PackArtifactBytes,
    evidence::{compile_evidence_pack_with_protocols, EvidenceLimits},
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

fn protocol_fixture(id: &str, config: &[u8]) -> (AdapterPack, PackArtifactBytes) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/examples/standalone/adapter-packs/synthetic-register");
    let mut value: Value =
        serde_json::from_slice(&fs::read(root.join("pack.yaml")).unwrap()).unwrap();
    value.as_object_mut().unwrap().remove("apiVersion");
    value.as_object_mut().unwrap().remove("kind");
    value["endpoints"][0]["hostProtocol"] = json!({
        "id":id,"config":{"path":"protocols/test.json","digest":registry_platform_config::sha256_uri(config)}
    });
    value["endpoints"][0]["authentication"] = json!({"type":"none"});
    let pack: AdapterPack = serde_json::from_value(value).unwrap();
    let mut files = vec![("protocols/test.json".to_owned(), config.to_vec())];
    for pin in pack.pinned_files() {
        if pin.path != "protocols/test.json" {
            files.push((pin.path.clone(), fs::read(root.join(&pin.path)).unwrap()));
        }
    }
    (pack, PackArtifactBytes::new(files))
}

fn checked_protocol(id: &str, config: &[u8]) -> bool {
    let (pack, artifacts) = protocol_fixture(id, config);
    compile_evidence_pack_with_protocols(
        &pack,
        "person",
        &artifacts,
        EvidenceLimits::default(),
        &registry_evidence::host_protocol::registry().unwrap(),
    )
    .is_ok()
}

#[test]
fn attribution_requires_explicit_selection_and_closed_empty_configuration() {
    assert!(checked_protocol("access-attribution-v1", b"{}"));
    for config in [
        br#"{"requester":"caller-controlled"}"#.as_slice(),
        b"null",
        b"[]",
    ] {
        assert!(!checked_protocol("access-attribution-v1", config));
    }
}

#[test]
fn unknown_protocol_and_incomplete_signed_contract_fail_before_live_binding() {
    assert!(!checked_protocol("unknown-protocol", b"{}"));
    assert!(!checked_protocol("signed-evidence-v1", b"{}"));
}

struct Intent;
impl registry_adapter_engine::evidence::EvidenceHostHooks for Intent {
    fn before_acquisition<'a>(
        &'a self,
        _intent: registry_adapter_engine::evidence::EvidenceAcquisitionIntent,
    ) -> registry_adapter_engine::evidence::EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn opted_in_attribution_preserves_get_body_absence_and_never_enters_facts() {
    use base64::Engine as _;
    use registry_adapter_core::EvidenceConnectionPolicy;
    use registry_adapter_engine::{
        evidence::{EvidenceLookup, EvidenceRuntimeBindings},
        host_protocol::HostAccessAttribution,
    };
    use registry_platform_config::{SecretProvider, SecretResolver};
    use std::sync::Arc;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };
    let server = MockServer::start().await;
    let encode = |value: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    Mock::given(method("GET"))
        .and(path("/people/0007"))
        .and(header(
            "registry-access-requester",
            encode("verified-requester"),
        ))
        .and(header("registry-access-purpose", encode("eligibility")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total":1,"record":{"record_id":"0007","birth_date":"1980-01-01",
                "residence_region":"north","address_canary":"synthetic"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (pack, artifacts) = protocol_fixture("access-attribution-v1", b"{}");
    let checked = compile_evidence_pack_with_protocols(
        &pack,
        "person",
        &artifacts,
        EvidenceLimits::default(),
        &registry_evidence::host_protocol::registry().unwrap(),
    )
    .unwrap();
    let runtime = EvidenceRuntimeBindings::new(
        serde_json::from_value(json!({"id":"local","endpoints":[{
            "endpoint":"register","baseUrl":server.uri(),"credential":{"type":"none"}
        }],"allowedPrivateCidrs":[]}))
        .unwrap(),
        SecretResolver::new([SecretProvider::Environment], "").unwrap(),
    );
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"register","baseUrl":server.uri(),"clientIdentity":"forbidden",
        "authentication":{"type":"none"}
    }))
    .unwrap();
    let program = checked
        .bind_live(&runtime, Some("local"), &[policy])
        .unwrap();
    assert!(program.requires_access_attribution());
    let without_context = program.begin_acquisition(Arc::new(Intent)).await.unwrap();
    assert!(program
        .execute(&without_context, json!({"recordId":"0007"}))
        .await
        .is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
    let acquisition = program
        .begin_acquisition_with_attribution(
            Arc::new(Intent),
            Arc::new(HostAccessAttribution::try_new("verified-requester", "eligibility").unwrap()),
        )
        .await
        .unwrap();
    let result = program
        .execute(&acquisition, json!({"recordId":"0007"}))
        .await;
    let requests_seen = server.received_requests().await.unwrap();
    assert!(
        result.is_ok(),
        "protocol execution failed: {:?}; recorded requests {}, header names {:?}",
        result.as_ref().err(),
        requests_seen.len(),
        requests_seen
            .iter()
            .map(|request| request
                .headers
                .keys()
                .map(|name| name.as_str())
                .collect::<Vec<_>>())
            .collect::<Vec<_>>()
    );
    let EvidenceLookup::Matched { facts } = result.unwrap() else {
        panic!("unique source match");
    };
    assert!(!facts.to_string().contains("verified-requester"));
    assert!(acquisition.trusted_protocol_metadata().await.is_empty());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].body.is_empty(),
        "GET must not acquire a body containing route inputs"
    );
    assert!(requests[0].url.query().is_none());
    server.verify().await;
}
