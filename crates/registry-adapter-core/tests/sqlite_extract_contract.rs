use registry_adapter_core::{AdapterPack, ComponentKind, SendComponent, SendUri};
use serde_json::json;

#[test]
fn sqlite_extract_is_a_reviewed_producer_without_http_authority() {
    let pack: AdapterPack = serde_json::from_value(json!({
        "id":"local-extract", "version":"0.1.0", "testedVersions":[],
        "endpoints":[{
            "id":"people", "component":"sqlite-extract", "authentication":{"type":"none"},
            "attemptTimeoutMilliseconds":2000, "maximumResponseBytes":8192,
            "sqliteExtract":{
                "extractProfile":"people", "statement":{"path":"queries/people.sql", "digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                "columns":[{"name":"id", "type":"string"}], "parameters":[{"name":"id", "required":true}],
                "maximumExtractAgeSeconds":3600, "maximumRows":2, "maximumCellBytes":1024,
                "maximumStatementSteps":100000, "concurrency":4
            }
        }]
    })).expect("reviewed SQLite endpoint");
    assert_eq!(pack.endpoints[0].component, ComponentKind::SqliteExtract);
    assert_eq!(
        SendUri::parse("sqlite-extract:people").unwrap().component,
        SendComponent::SqliteExtract
    );
    assert!(pack.endpoints[0].sqlite_extract.is_some());
    let mut document = serde_json::to_value(pack).unwrap();
    document["endpoints"][0]["sqliteExtract"]["path"] = json!("/arbitrary/live.sqlite");
    assert!(serde_json::from_value::<AdapterPack>(document).is_err());
}

#[test]
fn authored_check_refuses_missing_or_misplaced_sqlite_authority() {
    use registry_adapter_core::check_pack;
    let base = json!({"id":"extract","version":"0.1.0","testedVersions":[],"endpoints":[{
        "id":"people","component":"sqlite-extract","authentication":{"type":"none"},
        "attemptTimeoutMilliseconds":2000,"maximumResponseBytes":8192
    }]});
    let pack: AdapterPack = serde_json::from_value(base.clone()).unwrap();
    assert!(check_pack(&pack)
        .iter()
        .any(|finding| finding.code == "adapter.pack.sqlite-extract-invalid"));
    let mut http = base;
    http["endpoints"][0]["component"] = json!("http");
    http["endpoints"][0]["sqliteExtract"] = json!({
        "extractProfile":"people", "statement":{"path":"queries/people.sql","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        "columns":[{"name":"id","type":"string"}],"parameters":[],
        "maximumExtractAgeSeconds":3600,"maximumRows":2,"maximumCellBytes":1024,"maximumStatementSteps":100000,"concurrency":4
    });
    let pack: AdapterPack = serde_json::from_value(http).unwrap();
    assert!(check_pack(&pack)
        .iter()
        .any(|finding| finding.code == "adapter.pack.sqlite-extract-invalid"));
}

#[test]
fn evidence_only_route_does_not_require_ingestion_scan_cursors() {
    use registry_adapter_core::check_pack;
    let pin = json!({"path":"schemas/lookup.json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"});
    let pack: AdapterPack = serde_json::from_value(json!({
        "id":"lookup", "version":"0.1.0", "testedVersions":[],
        "sourceRoutes":[{"id":"person", "evidence":{"inputsSchema":pin,"factsSchema":pin},"steps":[]}]
    })).unwrap();
    let findings = check_pack(&pack);
    assert!(
        findings.is_empty(),
        "an Evidence lookup has no item scan: {findings:?}"
    );
}
