#![allow(
    clippy::disallowed_methods,
    reason = "the test mutates committed reviewed bundle and fixture YAML only inside disposable storage; it reads no operator configuration"
)]

use std::{collections::BTreeMap, fs, path::Path, path::PathBuf};

use registry_adapter_engine::route::EvidenceHttpDiagnostic;
use registry_evidence::{
    bundle::{evidence_package_limits, Bundle},
    config::{AuthorityKind, ValueOrigin},
    fixture_source::{compile_sources, fixture_acquisition},
    kernel::KernelError,
    model::LookupResult,
    selector::{
        ResolvedAuthorization, ResolvedSelectorField, ResolvedSelectorValue, ResolvedSubject,
        ResolvedSubjectScope,
    },
};
use serde_json::{json, Value};
use tempfile::TempDir;

const RECORD_REFERENCE: &str = "EeBJ3Sn9uLg";
const SOURCE_ID: &str = "population-tracker";

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("create temporary bundle directory");
    for entry in fs::read_dir(source).expect("read maintained reference bundle") {
        let entry = entry.expect("read maintained reference entry");
        let destination = target.join(entry.file_name());
        if entry
            .file_type()
            .expect("read maintained reference entry type")
            .is_dir()
        {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy maintained reference artifact");
        }
    }
}

fn projected_bundle() -> (TempDir, Bundle) {
    let repository = repository_root();
    let source = repository.join(
        "products/evidence/reference/request-adapter/deployment-projects/dhis2-tracker-evidence/bundle",
    );
    let temporary = tempfile::tempdir().expect("temporary Evidence bundle");
    copy_tree(&source, temporary.path());

    let config_path = temporary.path().join("evidence.yaml");
    let mut config: Value =
        serde_norway::from_slice(&fs::read(&config_path).expect("read copied Evidence config"))
            .expect("parse copied Evidence config");
    let maintained_pack =
        fs::read(repository.join("products/adapter/packs/dhis2-tracker/pack.yaml"))
            .expect("read maintained DHIS2 pack");
    let pack_digest = registry_platform_config::sha256_uri(&maintained_pack);
    let pack_hex = pack_digest
        .strip_prefix("sha256:")
        .expect("computed digest uses sha256 URI form");
    let projection = br#"fn project_facts(source) {
    let date_of_birth = ();
    for attribute in source.attributes {
        if attribute.attribute == "Dob00000001" {
            date_of_birth = attribute.value;
        }
    }
    if date_of_birth == () {
        throw "configured date-of-birth attribute is absent";
    }
    #{record_reference: source.trackedEntity, date_of_birth: date_of_birth}
}"#;
    let projection_path = "derivations/source-projections/dhis2-native.rhai";
    let schema_path = "schemas/source-facts/adult-status.schema.json";
    config["sources"][SOURCE_ID] = json!({
        "pack": {
            "id": "dhis2-tracker",
            "version": "1",
            "digest": pack_digest,
            "artifactPrefix": format!("adapter-packs/dhis2-tracker/{pack_hex}")
        },
        "route": "evidence-native-entity",
        "connection": "population-tracker",
        "inputs": {
            "recordReference": {
                "selector": {
                    "role": "subject",
                    "profile": "tracked-entity-reference-v1",
                    "field": "record_reference"
                }
            }
        },
        "posture": "record-transformed",
        "factSchema": schema_path,
        "projection": {
            "script": projection_path,
            "entrypoint": "project_facts",
            "digest": registry_platform_config::sha256_uri(projection)
        }
    });
    fs::write(
        &config_path,
        serde_norway::to_string(&config).expect("serialize extended Evidence config"),
    )
    .expect("write extended Evidence config");

    let projection_file = temporary.path().join(projection_path);
    fs::create_dir_all(projection_file.parent().expect("projection has a parent"))
        .expect("create projection directory");
    fs::write(projection_file, projection).expect("write package-owned projection");
    let schema_file = temporary.path().join(schema_path);
    fs::create_dir_all(schema_file.parent().expect("schema has a parent"))
        .expect("create projected facts schema directory");
    fs::write(
        schema_file,
        serde_json::to_vec_pretty(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://registry.example/schemas/dhis2-native-adult-status/1",
            "type": "object",
            "additionalProperties": false,
            "required": ["record_reference", "date_of_birth"],
            "properties": {
                "record_reference": {"type": "string", "minLength": 11, "maxLength": 64},
                "date_of_birth": {"type": "string", "format": "date"}
            }
        }))
        .expect("serialize projected facts schema"),
    )
    .expect("write projected facts schema");

    fs::remove_file(temporary.path().join(registry_platform_config::SUM_FILE))
        .expect("replace checksum closure only in disposable bundle");
    let verified = registry_platform_config::write_sum_file(
        temporary.path(),
        None,
        &evidence_package_limits(),
        "evidencectl package",
    )
    .expect("write exact checksum closure");
    let bundle = Bundle::load_as_found(temporary.path(), &verified)
        .expect("load native DHIS2 projection as a governed Evidence bundle");
    (temporary, bundle)
}

fn authorization() -> ResolvedAuthorization {
    ResolvedAuthorization {
        authority_profile: "native-projection-test".to_owned(),
        authority_kind: AuthorityKind::Statutory,
        grant_id: None,
        requirement: "native-projection-test".to_owned(),
        purpose: "benefit-eligibility".to_owned(),
        subject_scope: ResolvedSubjectScope::Audience(
            "urn:registry-evidence:dhis2-native-projection".to_owned(),
        ),
        subjects: vec![ResolvedSubject {
            role: "subject".to_owned(),
            selector_profile: "tracked-entity-reference-v1".to_owned(),
            value_origin: ValueOrigin::Request,
            fields: vec![ResolvedSelectorField {
                name: "record_reference".to_owned(),
                value: ResolvedSelectorValue::String(RECORD_REFERENCE.to_owned()),
            }],
        }],
    }
}

fn captured_acquisition(returned_record_reference: &str) -> Value {
    let fixture: Value = serde_norway::from_slice(
        &fs::read(repository_root().join("products/adapter/fixtures/dhis2-tracker/get-found.yaml"))
            .expect("read captured DHIS2 fixture"),
    )
    .expect("parse captured DHIS2 fixture");
    let mut exchanges = fixture["entries"][0]["upstream"].clone();
    exchanges[0]["request"]["headers"] = json!({"accept": "application/json"});
    exchanges[0]["response"]["body"]["trackedEntity"] = json!(returned_record_reference);
    exchanges[0]["response"]["body"]["attributes"]
        .as_array_mut()
        .expect("captured native entity carries attributes")
        .extend([
            json!({"attribute": "Dob00000001", "value": "2000-01-01"}),
            json!({"attribute": "Canary00001", "value": "private-canary"}),
        ]);
    json!({"intercepts": fixture["intercepts"], "exchanges": exchanges})
}

fn captured_http_failure(status: u16) -> Value {
    let fixture: Value = serde_norway::from_slice(
        &fs::read(repository_root().join("products/adapter/fixtures/dhis2-tracker/get-found.yaml"))
            .expect("read captured DHIS2 fixture"),
    )
    .expect("parse captured DHIS2 fixture");
    let mut exchanges = fixture["entries"][0]["upstream"].clone();
    exchanges[0]["request"]["headers"] = json!({"accept": "application/json"});
    exchanges[0]["response"] = json!({
        "status": status,
        "body": {
            "httpStatusCode": status,
            "status": "ERROR",
            "message": "PRIVATE-ERROR-CANARY"
        }
    });
    json!({"intercepts": fixture["intercepts"], "exchanges": exchanges})
}

#[tokio::test]
async fn maintained_native_dhis2_route_projects_facts_through_evidence_only() {
    let (_temporary, bundle) = projected_bundle();
    let programs = compile_sources(&bundle).expect("compile the listener-free Evidence sources");
    let source = programs
        .get(SOURCE_ID)
        .expect("the native projected source compiled");
    let observed_at = chrono::DateTime::parse_from_rfc3339("2026-08-02T00:00:00Z")
        .expect("parse fixed observation instant")
        .with_timezone(&chrono::Utc);

    let actual = source
        .execute(
            &authorization(),
            fixture_acquisition(&captured_acquisition(RECORD_REFERENCE))
                .expect("convert the captured native exchange"),
            observed_at,
        )
        .await
        .expect("replay the maintained native route through Evidence");
    assert_eq!(
        actual,
        LookupResult::Match(BTreeMap::from([
            ("date_of_birth".to_owned(), json!("2000-01-01")),
            ("record_reference".to_owned(), json!(RECORD_REFERENCE)),
        ]))
    );
    let LookupResult::Match(disclosed_facts) = &actual else {
        panic!("the native DHIS2 record did not remain a matched lookup");
    };
    let disclosed =
        serde_json::to_string(disclosed_facts).expect("serialize projected lookup facts");
    assert!(!disclosed.contains("private-canary"));
    assert!(!disclosed.contains("Synthetic text 01"));
    assert!(!disclosed.contains("attributes"));

    let mismatch = source
        .execute(
            &authorization(),
            fixture_acquisition(&captured_acquisition("WrongEntity1"))
                .expect("convert the mismatched captured exchange"),
            observed_at,
        )
        .await;
    assert!(matches!(mismatch, Err(KernelError::SourceProtocol)));
}

#[tokio::test]
async fn maintained_native_dhis2_route_normalizes_only_not_found_without_provider_values() {
    let (_temporary, bundle) = projected_bundle();
    let programs = compile_sources(&bundle).expect("compile the listener-free Evidence sources");
    let source = programs
        .get(SOURCE_ID)
        .expect("the native projected source compiled");
    let observed_at = chrono::DateTime::parse_from_rfc3339("2026-08-02T00:00:00Z")
        .expect("parse fixed observation instant")
        .with_timezone(&chrono::Utc);

    let not_found = source
        .execute_observed(
            &authorization(),
            fixture_acquisition(&captured_http_failure(404))
                .expect("convert the captured native 404 exchange"),
            None,
            observed_at,
        )
        .await;
    assert_eq!(not_found.outcome, Ok(LookupResult::NoMatch));
    assert_eq!(not_found.data_operations, 1);
    assert_eq!(not_found.http_cause, None);

    for (status, cause) in [
        (400, None),
        (500, Some(EvidenceHttpDiagnostic::ServerError)),
    ] {
        let failed = source
            .execute_observed(
                &authorization(),
                fixture_acquisition(&captured_http_failure(status))
                    .expect("convert the captured native failure exchange"),
                None,
                observed_at,
            )
            .await;
        assert!(matches!(&failed.outcome, Err(KernelError::SourceProtocol)));
        assert_eq!(
            failed.http_cause,
            cause.map(|cause| ("tracker".to_owned(), cause)),
            "HTTP {status} must retain only its value-free categorical cause"
        );
        let surfaced = format!("{:?} {:?}", failed.outcome, failed.http_cause);
        assert!(!surfaced.contains("PRIVATE-ERROR-CANARY"));
    }
}
