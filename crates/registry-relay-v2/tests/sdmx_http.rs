// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use http::header::{ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use jsonschema::{Draft, JSONSchema};
use registry_platform_audit::{AuditChainHasher, AuditEnvelope, AuditError, AuditSink, ChainState};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier};
use registry_platform_sqlite::{
    inspect_schema, materialize_fixture, CapturedSnapshot, DatabaseProfile, InspectionLimits,
    SchemaObjectKind,
};
use registry_platform_testing::{
    fixtures, oidc_verifier_config, sign_ed25519_compact_jwt, MockIdp,
};
use registry_relay_v2::artifacts::generate_artifacts;
use registry_relay_v2::audit::RelayAudit;
use registry_relay_v2::auth::RelayAuthenticator;
use registry_relay_v2::compiler::{
    classification_inventory_digest, compile_contract, compile_contract_with_governed_files,
    GovernedFileSet,
};
use registry_relay_v2::contract::{RegistryContract, RelayRuntime};
use registry_relay_v2::identification::{
    parse_classification_review_yaml, render_classification_review_yaml,
};
use registry_relay_v2::model::{
    CompileProfile, ObservedColumn, ObservedSourceSchema, ObservedView,
};
use registry_relay_v2::server::{
    router, AlignmentMetadata, InstitutionMetadata, QuotaConfig, RelayService, ServiceMetadata,
};
use registry_relay_v2::sqlite_runtime::{RuntimeSourceBinding, SqliteRuntime, SqliteRuntimeLimits};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt as _;

const PROJECT_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../products/relay-v2/acceptance/labour-statistics"
);
const PUBLIC_DATA: &str =
    "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F";
const PUBLIC_DATAFLOW: &str = "/sdmx/v2/structure/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0?references=none";
const PUBLIC_DSD: &str = "/sdmx/v2/structure/datastructure/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION_DSD/1.0.0?references=none";
const PROTECTED_DATA: &str =
    "/sdmx/v2/data/dataflow/EXAMPLE_STAT/LABOUR_FORCE_AUTHORITY/1.0.0/*?limit=4";
const PROTECTED_DATAFLOW: &str =
    "/sdmx/v2/structure/dataflow/EXAMPLE_STAT/LABOUR_FORCE_AUTHORITY/1.0.0?references=none";

struct Harness {
    app: axum::Router,
    runtime: RelayRuntime,
    idp: MockIdp,
    _temp: TempDir,
}

struct CapturedResponse {
    status: StatusCode,
    headers: HeaderMap,
    bytes: Vec<u8>,
}

impl CapturedResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).expect("response is JSON")
    }
}

struct ControlledAuditSink {
    fail_on_write: usize,
    writes: AtomicUsize,
    records: Mutex<Vec<Value>>,
}

impl ControlledAuditSink {
    fn new(fail_on_write: usize) -> Self {
        Self {
            fail_on_write,
            writes: AtomicUsize::new(0),
            records: Mutex::new(Vec::new()),
        }
    }

    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    fn values(&self) -> Vec<Value> {
        self.records.lock().expect("audit records lock").clone()
    }
}

#[async_trait::async_trait]
impl AuditSink for ControlledAuditSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        let write = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if write == self.fail_on_write {
            return Err(AuditError::Io(std::io::Error::other(
                "controlled audit failure",
            )));
        }
        self.records
            .lock()
            .expect("audit records lock")
            .push(envelope.record.clone());
        Ok(())
    }

    #[allow(deprecated)]
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }

    async fn tail_hash_with_hasher(
        &self,
        _hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(None)
    }
}

#[tokio::test]
async fn sdmx_data_and_structure_inherit_the_dataset_access_rule() {
    let harness = Harness::open(None, None).await;

    let public_data = harness.request(PUBLIC_DATA, None, None).await;
    assert_eq!(public_data.status, StatusCode::OK);
    assert_eq!(
        public_data.headers.get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("public, no-cache"))
    );
    assert!(public_data.headers.contains_key(ETAG));
    let public_structure = harness.request(PUBLIC_DATAFLOW, None, None).await;
    assert_eq!(public_structure.status, StatusCode::OK);
    assert_eq!(
        public_structure.headers.get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(
            "application/vnd.sdmx.structure+json;version=2.1.0"
        ))
    );

    for path in [PROTECTED_DATA, PROTECTED_DATAFLOW] {
        let response = harness.request(path, None, None).await;
        assert_problem(
            &response,
            StatusCode::UNAUTHORIZED,
            "auth.missing_credential",
        );
        assert_eq!(
            response.headers.get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }

    harness.stop().await;
}

#[tokio::test]
async fn protected_sdmx_structure_refusals_are_indistinguishable_and_value_free() {
    let sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let harness = Harness::open(None, Some(Arc::clone(&sink) as Arc<dyn AuditSink>)).await;
    let wrong_scope = harness.token(
        "wrong-scope",
        &["statistics:unrelated:read"],
        &[
            ("purpose", "official-planning"),
            ("area_authority", "zone-a"),
        ],
    );
    let concealed = harness
        .request(PROTECTED_DATAFLOW, None, Some(&wrong_scope))
        .await;
    let unknown = harness
        .request(
            "/sdmx/v2/structure/dataflow/EXAMPLE_STAT/UNKNOWN_FLOW/1.0.0?references=none",
            None,
            Some(&wrong_scope),
        )
        .await;
    assert_problem(&concealed, StatusCode::NOT_FOUND, "resource.not_found");
    assert_problem(&unknown, StatusCode::NOT_FOUND, "resource.not_found");
    let mut concealed_body = concealed.json();
    let mut unknown_body = unknown.json();
    concealed_body
        .as_object_mut()
        .expect("problem object")
        .remove("traceId");
    unknown_body
        .as_object_mut()
        .expect("problem object")
        .remove("traceId");
    assert_eq!(concealed_body, unknown_body);

    let known_anonymous = harness.request(PROTECTED_DATAFLOW, None, None).await;
    let unknown_anonymous = harness
        .request(
            "/sdmx/v2/structure/dataflow/PRIVATE_AGENCY/PRIVATE_FLOW/9.9.9",
            None,
            None,
        )
        .await;
    let invalid_type_anonymous = harness
        .request(
            "/sdmx/v2/structure/schema/PRIVATE_AGENCY/PRIVATE_FLOW/9.9.9",
            None,
            None,
        )
        .await;
    for response in [
        &known_anonymous,
        &unknown_anonymous,
        &invalid_type_anonymous,
    ] {
        assert_problem(
            response,
            StatusCode::UNAUTHORIZED,
            "auth.missing_credential",
        );
    }
    let mut known_body = known_anonymous.json();
    known_body
        .as_object_mut()
        .expect("problem object")
        .remove("traceId");
    for response in [unknown_anonymous, invalid_type_anonymous] {
        let mut body = response.json();
        body.as_object_mut()
            .expect("problem object")
            .remove("traceId");
        assert_eq!(body, known_body);
    }

    let audit_wire = serde_json::to_string(&sink.values()).expect("audit serializes");
    for value in ["wrong-scope", "zone-a", "UNKNOWN_FLOW", "official-planning"] {
        assert!(!audit_wire.contains(value), "audit disclosed {value}");
    }
    harness.stop().await;
}

#[tokio::test]
#[ignore = "explicitly fetches digest-locked official SDMX schemas"]
async fn generated_sdmx_outputs_validate_against_digest_locked_official_schemas() {
    let harness = Harness::open(None, None).await;
    let data = harness
        .request(
            concat!(
                "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?",
                "c%5BTIME_PERIOD%5D=2024-Q1&dimensionAtObservation=AllDimensions"
            ),
            Some("application/vnd.sdmx.data+json;version=2.1.0"),
            None,
        )
        .await;
    let csv = harness
        .request(
            concat!(
                "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?",
                "c%5BTIME_PERIOD%5D=2024-Q1"
            ),
            Some("application/vnd.sdmx.data+csv;version=2.1.0"),
            None,
        )
        .await;
    let dataflow = harness.request(PUBLIC_DATAFLOW, None, None).await;
    let dsd = harness.request(PUBLIC_DSD, None, None).await;
    for response in [&data, &csv, &dataflow, &dsd] {
        assert_eq!(response.status, StatusCode::OK);
    }
    let data_schema = official_schema(
        "https://json.sdmx.org/2.1.0/sdmx-json-data-schema.json",
        "ca1c85c7693a2d9d0602a1ca8e5a8b1cc56437fcb05e25cce15165ee75dcd80d",
        "https://json.sdmx.org/2.1/sdmx-json-data-schema.json",
    )
    .await;
    let structure_schema = official_schema(
        "https://json.sdmx.org/2.1.0/sdmx-json-structure-schema.json",
        "0f502a347cb463aee7664283ec53d79b6993bf5b503dc76151bb597d10ae3e32",
        "https://json.sdmx.org/2.1/sdmx-json-structure-schema.json",
    )
    .await;
    let data_validator = JSONSchema::options()
        .with_draft(Draft::Draft7)
        .should_validate_formats(true)
        .compile(&data_schema)
        .expect("official SDMX data schema compiles");
    let structure_validator = JSONSchema::options()
        .with_draft(Draft::Draft7)
        .should_validate_formats(true)
        .compile(&structure_schema)
        .expect("official SDMX structure schema compiles");
    assert!(data_validator.is_valid(&data.json()));
    assert!(structure_validator.is_valid(&dataflow.json()));
    assert!(structure_validator.is_valid(&dsd.json()));
    let rows = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(csv.bytes.as_slice())
        .records()
        .collect::<Result<Vec<_>, _>>()
        .expect("SDMX-CSV reads");
    let header = rows.first().expect("SDMX-CSV has a header");
    assert!(header.len() >= 4);
    assert_eq!(
        header.iter().take(3).collect::<Vec<_>>(),
        ["STRUCTURE", "STRUCTURE_ID", "ACTION"]
    );
    assert!(rows.iter().skip(1).all(|row| row.len() == header.len()));
    harness.stop().await;
}

async fn official_schema(url: &str, digest: &str, identifier: &str) -> Value {
    let bytes = reqwest::get(url)
        .await
        .expect("official SDMX schema fetches")
        .error_for_status()
        .expect("official SDMX schema returns success")
        .bytes()
        .await
        .expect("official SDMX schema reads");
    assert_eq!(hex::encode(Sha256::digest(&bytes)), digest);
    let schema: Value = serde_json::from_slice(&bytes).expect("official SDMX schema is JSON");
    assert_eq!(schema["$id"], identifier);
    schema
}

#[tokio::test]
async fn sdmx_denial_mapping_is_fixed_and_value_free() {
    let sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let harness = Harness::open(None, Some(Arc::clone(&sink) as Arc<dyn AuditSink>)).await;
    let wrong_scope = harness.token(
        "wrong-scope",
        &["statistics:unrelated:read"],
        &[
            ("purpose", "official-planning"),
            ("area_authority", "zone-a"),
        ],
    );
    let wrong_purpose = harness.token(
        "wrong-purpose",
        &["statistics:labour-authority:read"],
        &[
            ("purpose", "commercial-profiling"),
            ("area_authority", "zone-a"),
        ],
    );
    let missing_binding = harness.token(
        "missing-binding",
        &["statistics:labour-authority:read"],
        &[("purpose", "official-planning")],
    );

    let cases = [
        (None, StatusCode::UNAUTHORIZED, "auth.missing_credential"),
        (
            Some(wrong_scope.as_str()),
            StatusCode::NOT_FOUND,
            "resource.not_found",
        ),
        (
            Some(wrong_purpose.as_str()),
            StatusCode::FORBIDDEN,
            "aggregate-data.denied",
        ),
        (
            Some(missing_binding.as_str()),
            StatusCode::FORBIDDEN,
            "aggregate-data.denied",
        ),
    ];
    for (token, status, code) in cases {
        let response = harness.request(PROTECTED_DATA, None, token).await;
        assert_problem(&response, status, code);
    }
    let response_wire = serde_json::to_string(&sink.values()).expect("audit serializes");
    for value in [
        "wrong-scope",
        "wrong-purpose",
        "missing-binding",
        "commercial-profiling",
        "zone-a",
    ] {
        assert!(!response_wire.contains(value), "refusal disclosed {value}");
    }
    harness.stop().await;
}

#[tokio::test]
async fn sdmx_json_preserves_declared_scalar_types() {
    let harness = Harness::open(None, None).await;
    let response = harness
        .request(
            concat!(
                "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?",
                "c%5BTIME_PERIOD%5D=2024-Q1&dimensionAtObservation=AllDimensions"
            ),
            Some("application/vnd.sdmx.data+json;version=2.1.0"),
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let document = response.json();
    assert!(document["$schema"].as_str().is_some());
    for index in 0..3 {
        let values = document
            .pointer(&format!(
                "/data/structures/0/dimensions/observation/{index}/values"
            ))
            .and_then(Value::as_array)
            .expect("dimension values");
        assert!(values.iter().all(|value| {
            value
                .get("id")
                .or_else(|| value.get("value"))
                .is_some_and(Value::is_string)
        }));
    }
    assert_eq!(
        document.pointer("/data/structures/0/measures/observation/0/format/dataType"),
        Some(&json!("Decimal"))
    );
    let observation = document
        .pointer("/data/dataSets/0/observations/0:0:0")
        .and_then(Value::as_array)
        .expect("one flat observation");
    assert!(observation[0].is_number(), "measure remains a JSON number");
    assert!(
        observation[1].is_number(),
        "coded attribute is an SDMX value index"
    );
    harness.stop().await;
}

#[tokio::test]
async fn duplicate_sdmx_observation_keys_fail_closed_across_page_boundaries() {
    let original = fixture_sql();
    let without_key = original.replace(
        "    authority_scope TEXT NOT NULL,\n    PRIMARY KEY (ref_area, sex, time_period)\n",
        "    authority_scope TEXT NOT NULL\n",
    );
    assert_ne!(without_key, original, "fixture primary key is removed");
    let duplicated = without_key.replace(
        "('EX-B', 'X', '2024-Q2', 70.0, 'PERCENT', 'zone-b');",
        concat!(
            "('EX-B', 'X', '2024-Q2', 70.0, 'PERCENT', 'zone-b'),\n",
            "('EX-A', 'F', '2024-Q1', 99.9, 'PERCENT', 'zone-a');"
        ),
    );
    assert_ne!(duplicated, without_key, "duplicate observation is inserted");
    let sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let harness = Harness::open(
        Some(duplicated),
        Some(Arc::clone(&sink) as Arc<dyn AuditSink>),
    )
    .await;
    let response = harness
        .request(
            concat!(
                "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?",
                "c%5BTIME_PERIOD%5D=2024-Q1&limit=1&offset=1"
            ),
            None,
            None,
        )
        .await;
    assert_problem(
        &response,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );
    let wire = String::from_utf8(response.bytes).expect("problem is UTF-8");
    assert!(!wire.contains("99.9"));
    let records = sink.values();
    assert_eq!(records[0]["phase"], "attempt");
    assert_eq!(records[1]["phase"], "terminal");
    assert_eq!(records[1]["outcome"], "source-failed");
    harness.stop().await;
}

#[tokio::test]
async fn sdmx_source_rows_must_use_governed_codelist_values() {
    let dimension_sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let dimension_harness = Harness::open(
        None,
        Some(Arc::clone(&dimension_sink) as Arc<dyn AuditSink>),
    )
    .await;
    let dimension_response = dimension_harness
        .request(
            concat!(
                "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-B.X?",
                "c%5BTIME_PERIOD%5D=2024-Q2"
            ),
            None,
            None,
        )
        .await;
    assert_source_code_refusal(&dimension_response, &dimension_sink, &["\"X\"", "70.0"]);
    dimension_harness.stop().await;

    let original = fixture_sql();
    let invalid_attribute = original.replacen("'PERCENT'", "'UNKNOWN_UNIT'", 1);
    assert_ne!(invalid_attribute, original);
    let attribute_sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let attribute_harness = Harness::open(
        Some(invalid_attribute),
        Some(Arc::clone(&attribute_sink) as Arc<dyn AuditSink>),
    )
    .await;
    let attribute_response = attribute_harness
        .request(
            concat!(
                "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-A.F?",
                "c%5BTIME_PERIOD%5D=2024-Q1"
            ),
            None,
            None,
        )
        .await;
    assert_source_code_refusal(
        &attribute_response,
        &attribute_sink,
        &["\"UNKNOWN_UNIT\"", "61.2"],
    );
    attribute_harness.stop().await;
}

fn assert_source_code_refusal(
    response: &CapturedResponse,
    sink: &ControlledAuditSink,
    hidden: &[&str],
) {
    assert_problem(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "source.unavailable",
    );
    let records = sink.values();
    assert_eq!(records.len(), 2, "attempt and terminal audit are atomic");
    assert_eq!(records[0]["phase"], "attempt");
    assert_eq!(records[1]["phase"], "terminal");
    assert_eq!(records[1]["outcome"], "source-failed");
    let wire = format!(
        "{}{}",
        String::from_utf8_lossy(&response.bytes),
        serde_json::to_string(&records).expect("audit serializes")
    );
    for value in hidden {
        assert!(!wire.contains(value), "source value {value} escaped");
    }
}

#[tokio::test]
async fn sdmx_data_and_structure_use_distinct_value_free_audit_surfaces() {
    let sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let harness = Harness::open(None, Some(Arc::clone(&sink) as Arc<dyn AuditSink>)).await;
    for path in [PUBLIC_DATA, PUBLIC_DATAFLOW, PUBLIC_DSD] {
        let response = harness.request(path, None, None).await;
        assert_eq!(response.status, StatusCode::OK);
    }
    let invalid_query = harness
        .request(
            "/sdmx/v2/structure/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0?references=all",
            None,
            None,
        )
        .await;
    assert_problem(
        &invalid_query,
        StatusCode::BAD_REQUEST,
        "aggregate-data.invalid_request",
    );
    let unsupported = harness
        .request(PUBLIC_DATAFLOW, Some("application/xml"), None)
        .await;
    assert_problem(
        &unsupported,
        StatusCode::NOT_ACCEPTABLE,
        "format.unsupported",
    );
    let records = sink.values();
    let attempts = records
        .iter()
        .filter(|record| record["phase"] == "attempt")
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 3);
    assert_eq!(attempts[0]["operationSurface"], "sdmx-data");
    assert_eq!(attempts[0]["wireFormat"], "sdmx-json");
    assert_eq!(attempts[0]["queryShape"], "sdmx-keyed-time-period");
    assert_eq!(attempts[1]["operationSurface"], "sdmx-dataflow-structure");
    assert_eq!(attempts[1]["wireFormat"], "sdmx-structure-json");
    assert_eq!(
        attempts[2]["operationSurface"],
        "sdmx-datastructure-structure"
    );
    assert_eq!(attempts[2]["wireFormat"], "sdmx-structure-json");
    assert!(attempts.iter().all(|record| {
        record["operationIdentifier"] == "labour-force-participation.statistics.read"
            && record.get("accessProfile").is_none()
            && record.get("disclosureProfile").is_none()
    }));
    let refusals = records
        .iter()
        .filter(|record| record["phase"] == "refusal")
        .collect::<Vec<_>>();
    assert_eq!(refusals.len(), 2);
    assert_eq!(refusals[0]["wireFormat"], "sdmx-structure-json");
    assert!(refusals[1].get("wireFormat").is_none());
    let wire = serde_json::to_string(&attempts).expect("audit serializes");
    for value in ["EX-A", "2024-Q1", "references"] {
        assert!(!wire.contains(value), "audit disclosed {value}");
    }
    harness.stop().await;
}

#[tokio::test]
async fn sdmx_json_and_csv_terminal_audits_bind_exact_wire_bytes() {
    for (accept, expected_wire, held_values) in [
        (
            "application/vnd.sdmx.data+json;version=2.1.0",
            "sdmx-json",
            &["$schema", "61.2", "EX-A"][..],
        ),
        (
            "application/vnd.sdmx.data+csv;version=2.1.0",
            "sdmx-csv",
            &["STRUCTURE", "61.2", "EX-A"][..],
        ),
    ] {
        let sink = Arc::new(ControlledAuditSink::new(2));
        let harness = Harness::open(None, Some(Arc::clone(&sink) as Arc<dyn AuditSink>)).await;
        let response = harness.request(PUBLIC_DATA, Some(accept), None).await;
        assert_problem(
            &response,
            StatusCode::SERVICE_UNAVAILABLE,
            "audit.unavailable",
        );
        let wire = String::from_utf8(response.bytes).expect("problem is UTF-8");
        for held in held_values {
            assert!(!wire.contains(held), "held {expected_wire} bytes escaped");
        }
        assert_eq!(sink.writes(), 2);
        let records = sink.values();
        assert_eq!(records.len(), 1, "only the attempt audit commits");
        assert_eq!(records[0]["wireFormat"], expected_wire);
        harness.stop().await;
    }
}

#[tokio::test]
async fn sdmx_attempt_audit_failure_prevents_sqlite_execution() {
    let sink = Arc::new(ControlledAuditSink::new(1));
    let harness = Harness::open(None, Some(Arc::clone(&sink) as Arc<dyn AuditSink>)).await;
    let response = harness.request(PUBLIC_DATA, None, None).await;
    assert_problem(
        &response,
        StatusCode::SERVICE_UNAVAILABLE,
        "audit.unavailable",
    );
    assert_eq!(
        sink.writes(),
        1,
        "request stops at the failed attempt audit"
    );
    assert!(sink.values().is_empty());
    harness.stop().await;
}

#[tokio::test]
async fn authorized_sdmx_query_without_observations_is_value_free_not_found() {
    let sink = Arc::new(ControlledAuditSink::new(usize::MAX));
    let harness = Harness::open(None, Some(Arc::clone(&sink) as Arc<dyn AuditSink>)).await;
    let response = harness
        .request(
            concat!(
                "/sdmx/v2/data/dataflow/LABOUR_STATISTICS/LABOUR_FORCE_PARTICIPATION/1.0.0/EX-Z.F?",
                "c%5BTIME_PERIOD%5D=2024-Q3"
            ),
            None,
            None,
        )
        .await;
    assert_problem(&response, StatusCode::NOT_FOUND, "resource.not_found");
    let records = sink.values();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["phase"], "attempt");
    assert_eq!(records[1]["phase"], "terminal");
    assert_eq!(records[1]["outcome"], "not-found");
    let wire = format!(
        "{}{}",
        String::from_utf8(response.bytes).expect("problem is UTF-8"),
        serde_json::to_string(&records).expect("audit serializes")
    );
    for value in ["EX-Z", "2024-Q3"] {
        assert!(!wire.contains(value), "empty selector {value} escaped");
    }
    harness.stop().await;
}

impl Harness {
    async fn open(fixture_override: Option<String>, sink: Option<Arc<dyn AuditSink>>) -> Self {
        let root = Path::new(PROJECT_ROOT);
        let contract_yaml = fs::read_to_string(root.join("registry.yaml")).expect("contract reads");
        let mut contract = RegistryContract::parse_yaml(&contract_yaml).expect("contract parses");
        let runtime = RelayRuntime::parse_yaml(
            &fs::read_to_string(root.join("runtime.yaml")).expect("runtime reads"),
        )
        .expect("runtime parses");
        let fixture = fixture_override.unwrap_or_else(fixture_sql);
        let temp = tempfile::tempdir().expect("temporary project creates");
        let database = temp.path().join("fixture.sqlite");
        materialize_fixture(&database, &fixture).expect("fixture materializes");
        let catalog = inspect_schema(
            &DatabaseProfile::Snapshot(
                CapturedSnapshot::capture(&database).expect("fixture captures"),
            ),
            &InspectionLimits {
                maximum_objects: 10_000,
                maximum_sql_bytes: 8 * 1024 * 1024,
                maximum_statement_steps: 1_000_000,
                timeout: Duration::from_secs(5),
            },
        )
        .expect("schema inspects");
        let source_id = contract
            .sources
            .keys()
            .next()
            .expect("one source")
            .to_owned();
        let governed_fingerprint = contract
            .sources
            .get(&source_id)
            .expect("fixture source")
            .expected_schema_fingerprint
            .clone();
        if governed_fingerprint != catalog.fingerprint {
            let rewritten = contract_yaml.replacen(&governed_fingerprint, &catalog.fingerprint, 1);
            contract =
                RegistryContract::parse_yaml(&rewritten).expect("fixture-governed contract parses");
        }
        let observed = vec![ObservedSourceSchema {
            source: source_id.clone(),
            fingerprint: catalog.fingerprint.clone(),
            views: catalog
                .objects
                .into_iter()
                .filter(|object| object.kind == SchemaObjectKind::View)
                .map(|object| ObservedView {
                    name: object.name,
                    columns: object
                        .columns
                        .into_iter()
                        .map(|column| ObservedColumn {
                            name: column.name,
                            declared_type: column.declared_type,
                            nullable: column.nullable,
                            primary_key: column.primary_key,
                        })
                        .collect(),
                })
                .collect(),
        }];
        let mut governed = governed_files(root, &contract);
        let inventory = compile_contract(&contract, &observed, CompileProfile::Production)
            .expect("fixture inventory compiles");
        let inventory_digest =
            classification_inventory_digest(&inventory).expect("fixture inventory digests");
        if governed_fingerprint != catalog.fingerprint {
            let path = contract.classifications.provenance_ref.clone();
            let mut review = parse_classification_review_yaml(
                governed
                    .get(&path)
                    .expect("classification review is governed"),
            )
            .expect("classification review parses");
            review.classification_inventory_digest = inventory_digest;
            governed.insert(
                path,
                render_classification_review_yaml(&review).expect("classification review renders"),
            );
        } else {
            let review = parse_classification_review_yaml(
                governed
                    .get(&contract.classifications.provenance_ref)
                    .expect("classification review is governed"),
            )
            .expect("classification review parses");
            assert_eq!(
                review.classification_inventory_digest, inventory_digest,
                "labour-statistics classification review is stale"
            );
        }
        let compiled = Arc::new(
            compile_contract_with_governed_files(
                &contract,
                &observed,
                CompileProfile::Production,
                &governed,
            )
            .unwrap_or_else(|report| panic!("labour-statistics compilation failed: {report:?}")),
        );
        let artifacts = Arc::new(generate_artifacts(&compiled).expect("artifacts generate"));
        let sqlite = Arc::new(
            SqliteRuntime::open(
                &compiled,
                &BTreeMap::from([(
                    source_id,
                    RuntimeSourceBinding {
                        path: database.clone(),
                    },
                )]),
                SqliteRuntimeLimits {
                    request_timeout: Duration::from_millis(
                        runtime.limits.request_timeout_milliseconds,
                    ),
                    concurrent_queries: usize::try_from(runtime.limits.concurrent_queries)
                        .expect("query limit fits"),
                },
            )
            .expect("SQLite runtime opens"),
        );
        let sink = sink.unwrap_or_else(|| Arc::new(ControlledAuditSink::new(usize::MAX)));
        let chain = Arc::new(
            ChainState::bootstrap_unkeyed_dev_only(sink.as_ref())
                .await
                .expect("test audit chain starts"),
        );
        let audit = RelayAudit::new(chain, sink);
        let idp = MockIdp::start().await;
        let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        ));
        fetcher.ensure_key_set().await.expect("fixture JWKS loads");
        let issuer = runtime
            .authentication
            .issuer
            .as_ref()
            .expect("statistical runtime has issuer");
        let mut verifier = oidc_verifier_config(idp.issuer(), vec![issuer.audience.clone()]);
        verifier.allowed_typ = vec!["at+jwt".into()];
        verifier.max_token_lifetime = Some(Duration::from_secs(3600));
        let authenticator = RelayAuthenticator::new(
            Arc::new(TokenVerifier::new(verifier, fetcher)),
            issuer.audience.clone(),
            Duration::from_secs(30),
        );
        let metadata = ServiceMetadata {
            authority: InstitutionMetadata {
                identifier: contract.registry.authority.identifier.clone(),
                name: contract.registry.authority.name.clone(),
            },
            operator: contract
                .registry
                .operator
                .as_ref()
                .map(|operator| InstitutionMetadata {
                    identifier: operator.identifier.clone(),
                    name: operator.name.clone(),
                }),
            authoritative_scope: contract.registry.authoritative_scope.clone(),
            alignment_targets: contract
                .registry
                .alignment_targets
                .iter()
                .map(|target| AlignmentMetadata {
                    name: target.name.clone(),
                    version: target.version.clone(),
                    status: target.status.clone(),
                    cfr_target: target.cfr_target.clone(),
                })
                .collect(),
        };
        let service = Arc::new(RelayService::new(
            compiled,
            artifacts,
            sqlite,
            Some(authenticator),
            audit,
            None,
            Duration::from_secs(300),
            Duration::from_millis(runtime.limits.request_timeout_milliseconds),
            runtime.quotas.as_ref().map(|quota| QuotaConfig {
                requests_per_minute: quota.requests_per_minute,
                burst: quota.burst,
            }),
            metadata,
        ));
        Self {
            app: router(service),
            runtime,
            idp,
            _temp: temp,
        }
    }

    async fn request(
        &self,
        uri: &str,
        accept: Option<&str>,
        bearer: Option<&str>,
    ) -> CapturedResponse {
        let mut request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request builds");
        if let Some(accept) = accept {
            request
                .headers_mut()
                .insert(ACCEPT, accept.parse().expect("Accept header"));
        }
        if let Some(bearer) = bearer {
            request.headers_mut().insert(
                AUTHORIZATION,
                format!("Bearer {bearer}")
                    .parse()
                    .expect("Authorization header"),
            );
        }
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("router responds");
        capture(response).await
    }

    fn token(&self, subject: &str, scopes: &[&str], claims: &[(&str, &str)]) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is valid")
            .as_secs();
        let audience = &self
            .runtime
            .authentication
            .issuer
            .as_ref()
            .expect("runtime has issuer")
            .audience;
        let mut document = serde_json::Map::from_iter([
            ("iss".into(), json!(self.idp.issuer())),
            ("aud".into(), json!(audience)),
            ("sub".into(), json!(subject)),
            ("scope".into(), json!(scopes.join(" "))),
            ("iat".into(), json!(now)),
            ("nbf".into(), json!(now)),
            ("exp".into(), json!(now.saturating_add(900))),
            ("jti".into(), json!(format!("fixture-{subject}-{now}"))),
        ]);
        for (name, value) in claims {
            document.insert((*name).into(), json!(value));
        }
        sign_ed25519_compact_jwt(
            fixtures::ED25519_PRIVATE_JWK,
            "at+jwt",
            "registry-platform-testing-ed25519-1",
            Value::Object(document),
        )
    }

    async fn stop(self) {
        self.idp.stop().await;
    }
}

async fn capture(response: Response<Body>) -> CapturedResponse {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .expect("response body reads")
        .to_vec();
    CapturedResponse {
        status,
        headers,
        bytes,
    }
}

fn assert_problem(response: &CapturedResponse, status: StatusCode, code: &str) {
    assert_eq!(response.status, status);
    assert_eq!(response.json()["code"], code);
    assert_eq!(
        response.headers.get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
}

fn fixture_sql() -> String {
    fs::read_to_string(Path::new(PROJECT_ROOT).join("fixture.sql")).expect("fixture SQL reads")
}

fn governed_files(root: &Path, contract: &RegistryContract) -> GovernedFileSet {
    let mut paths = BTreeSet::new();
    paths.insert(contract.registry.identifier_lifecycle_policy_ref.clone());
    paths.insert(contract.classifications.provenance_ref.clone());
    let review = parse_classification_review_yaml(
        &fs::read(root.join(&contract.classifications.provenance_ref))
            .expect("classification review reads"),
    )
    .expect("classification review parses");
    paths.insert(review.rationale_ref);
    if let Some(generated) = review.generated_identification {
        paths.insert(generated.report_ref);
    }
    for alignment in &contract.semantics.alignments {
        paths.insert(alignment.profile_ref.clone());
    }
    for dataset in &contract.statistical_datasets {
        for (_, dimension) in dataset.dimensions.iter() {
            if let Some(path) = &dimension.vocabulary {
                paths.insert(path.clone());
            }
        }
        for (_, attribute) in dataset.attributes.iter() {
            if let Some(path) = &attribute.vocabulary {
                paths.insert(path.clone());
            }
        }
        for processing in &dataset.processing_descriptions {
            paths.insert(processing.legal_basis_ref.clone());
            paths.insert(processing.dpv_profile_ref.clone());
        }
    }
    paths
        .into_iter()
        .map(|path| {
            let bytes = fs::read(root.join(&path))
                .unwrap_or_else(|error| panic!("governed file {path} reads: {error}"));
            (path, bytes)
        })
        .collect()
}
