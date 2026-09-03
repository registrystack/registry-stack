// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

use std::collections::BTreeSet;
use std::sync::Arc;

#[path = "support/pilot_acceptance_harness.rs"]
#[allow(dead_code)]
mod pilot_acceptance_harness;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::body::Body;
use axum::http::{Method, Response, StatusCode};
use jsonschema::{Draft, JSONSchema};
use pilot_acceptance_harness::{response_bytes, response_json, PilotHarness};
use registry_breg_client::{
    BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey, BRegListRequest, BRegPatchRequest,
    BRegProblemCode, BRegRecordFormat, BRegRecordOptions, BaseRegistryClient,
    BaseRegistryClientConfig, StaticToken,
};
use serde_json::{json, Value};
use uuid::Uuid;

const PROFILE_IDENTIFIER: &str = "https://id.registrystack.org/profiles/registry-record/v1";
const BREG_REGISTRY_IDENTIFIER: &str = "cross-product-conformance";
const CONTEXT_IDENTIFIER: &str = "https://id.registrystack.org/contexts/registry-record/v1";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_registry_record_profile_matches_the_cross_product_semantic_gold() {
    let gold = semantic_gold();
    let public = dataset(&gold, "public");
    let protected = dataset(&gold, "protected");
    let harness = PilotHarness::start("registry-record-conformance").await;

    let writer = harness.token_with_scopes("fixture-setup", &[], &["records:fixture:write"]);
    let public_identifier = create_record(&harness, "public-units", &writer, public).await;
    let protected_identifier = create_record(&harness, "protected-units", &writer, protected).await;
    let protected_reader =
        harness.token_with_scopes("bounded-read", &[], &["records:protected:read"]);

    let public_single_uri = format!("/v1/records/public-units/{public_identifier}");
    let public_json = get_success(&harness, &public_single_uri, None, "application/json").await;
    assert_profile_link(&public_json.headers);
    assert_shared_single(&public_json.document, &gold, public, false);

    let public_json_ld =
        get_success(&harness, &public_single_uri, None, "application/ld+json").await;
    assert_profile_link(&public_json_ld.headers);
    assert_shared_single(&public_json_ld.document, &gold, public, true);

    let public_list_json = get_success(
        &harness,
        "/v1/records/public-units",
        None,
        "application/json",
    )
    .await;
    assert_profile_link(&public_list_json.headers);
    assert_shared_collection(&public_list_json.document, &gold, public, false);

    let public_list_json_ld = get_success(
        &harness,
        "/v1/records/public-units",
        None,
        "application/ld+json",
    )
    .await;
    assert_profile_link(&public_list_json_ld.headers);
    assert_shared_collection(&public_list_json_ld.document, &gold, public, true);

    let protected_single_uri = format!(
        "/v1/records/protected-units/{protected_identifier}?accessProfile=protected-reader"
    );
    let protected_json = get_success(
        &harness,
        &protected_single_uri,
        Some(&protected_reader),
        "application/json",
    )
    .await;
    assert_profile_link(&protected_json.headers);
    assert_shared_single(&protected_json.document, &gold, protected, false);

    let protected_list = get_success(
        &harness,
        "/v1/records/protected-units?accessProfile=protected-reader",
        Some(&protected_reader),
        "application/json",
    )
    .await;
    assert_profile_link(&protected_list.headers);
    assert_shared_collection(&protected_list.document, &gold, protected, false);

    let unauthorized = harness
        .send(Method::GET, &protected_single_uri, None, &[], Vec::new())
        .await;
    let unknown = harness
        .send(
            Method::GET,
            &format!(
                "/v1/records/unknown-units/{protected_identifier}?accessProfile=protected-reader"
            ),
            Some(&protected_reader),
            &[],
            Vec::new(),
        )
        .await;
    assert_concealed_equivalence(unauthorized, unknown, protected).await;

    let public_openapi = caller_openapi(&harness, "public-reader", None).await;
    let public_openapi_text = public_openapi.to_string();
    assert!(!public_openapi_text.contains("protected-units"));
    assert!(!public_openapi_text.contains("PROTECTED-SEMANTIC-CANARY"));
    validate_exact_responses(
        &public_openapi,
        "/v1/records/public-units/{record_id}",
        "get",
        &public_json.document,
        &public_json_ld.document,
    );
    validate_exact_responses(
        &public_openapi,
        "/v1/records/public-units",
        "get",
        &public_list_json.document,
        &public_list_json_ld.document,
    );

    let protected_openapi =
        caller_openapi(&harness, "protected-reader", Some(&protected_reader)).await;
    assert!(protected_openapi["paths"]
        .get("/v1/records/protected-units/{record_id}")
        .is_some());
    assert!(protected_openapi["paths"]
        .get("/v1/records/public-units/{record_id}")
        .is_none());
    let protected_validator = exact_response_validator(
        &protected_openapi,
        "/v1/records/protected-units/{record_id}",
        "get",
        "application/json",
    );
    assert!(protected_validator.is_valid(&protected_json.document));
    assert_meta_constant_mutations_are_rejected(&protected_validator, &protected_json.document);

    let base_validator = shared_base_validator();
    assert!(base_validator.is_valid(&public_json.document));
    assert!(base_validator.is_valid(&public_list_json.document));
    let mut base_extension = public_json.document.clone();
    base_extension["data"]["domainData"]["productExtension"] = json!("allowed-by-base");
    assert!(
        base_validator.is_valid(&base_extension),
        "the shared base keeps domainData open for product-owned fields"
    );
    let public_exact = exact_response_validator(
        &public_openapi,
        "/v1/records/public-units/{record_id}",
        "get",
        "application/json",
    );
    assert!(
        !public_exact.is_valid(&base_extension),
        "the exact generated entity schema closes the emitted domainData shape"
    );

    let second_public_identifier = create_additional_record(
        &harness,
        "public-units",
        &writer,
        "seed-public-units-client-continuation",
        json!({"label": "PUBLIC-CLIENT-CONTINUATION-CANARY"}),
    )
    .await;
    let http_server = harness.serve_http().await;
    exercise_breg_client(
        http_server.base_url(),
        &public_identifier,
        &second_public_identifier,
        &protected_identifier,
        &protected_reader,
        public,
        protected,
    )
    .await;
    http_server.finish().await;

    let dcat = artifact_json(&harness, "generated/manifest/dcat.jsonld");
    let dcat_text = dcat.to_string();
    assert!(dcat_text.contains("public-units"));
    for absent in [
        "protected-units",
        "protected-unit",
        "PROTECTED-SEMANTIC-CANARY",
    ] {
        assert!(
            !dcat_text.contains(absent),
            "public DCAT disclosed {absent}"
        );
    }

    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn breg_client_executes_metadata_bound_direct_writes_against_real_postgres() {
    let harness = PilotHarness::start("asset-site-placement-change-requests").await;
    let token = harness.token("asset-management", &[]);
    let http_server = harness.serve_http().await;
    let client = BaseRegistryClient::new(
        BaseRegistryClientConfig::new(
            http_server
                .base_url()
                .parse()
                .expect("pilot loopback URL parses"),
        )
        .with_token_provider(Arc::new(
            StaticToken::new(&token).expect("MockIdp token is an outbound bearer value"),
        )),
    )
    .expect("authenticated Base Registry Engine client config is valid");

    let metadata = client
        .registry_contract(Some("asset-operator"))
        .await
        .expect("authorized caller receives strict caller-filtered runtime metadata");
    assert_eq!(
        metadata.value.registry_identifier(),
        "asset-site-placement-change-requests"
    );
    assert_eq!(
        metadata.value.registry_revision(),
        harness.registry.revision()
    );
    assert!(metadata
        .value
        .operations()
        .iter()
        .all(|operation| operation.access_profile() == "asset-operator"));

    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.asset-item.create", "asset-operator")
        .expect("exact direct Create contract is executable")
    else {
        panic!("selected operation must be Create")
    };
    let BRegDirectWrite::Patch(patch) = metadata
        .value
        .select_direct_write("records.asset-item.patch", "asset-operator")
        .expect("exact direct PATCH contract is executable")
    else {
        panic!("selected operation must be PATCH")
    };
    assert_eq!(create.path(), "/v1/records/assets");
    assert_eq!(create.entity_identifier(), "asset-item");
    assert_eq!(patch.entity_identifier(), create.entity_identifier());
    assert_eq!(patch.registry_revision(), create.registry_revision());

    let create_request = BRegCreateRequest::new(
        json!({
            "assetCode": "CLIENT-PG-001",
            "label": "Client PostgreSQL journey",
            "assetClass": "equipment"
        })
        .as_object()
        .expect("create data is an object")
        .clone(),
    )
    .expect("create body follows the metadata-bound field contract");
    let create_key = BRegIdempotencyKey::parse("client-pg-create")
        .expect("fixture Create idempotency key is valid");
    let created = client
        .create_record(
            &create,
            &create_request,
            &create_key,
            BRegRecordFormat::Json,
        )
        .await
        .expect("metadata-bound Create succeeds against real PostgreSQL");
    assert_registry_record(
        &created.value,
        "asset-item",
        "1",
        &json!({
            "assetCode": "CLIENT-PG-001",
            "label": "Client PostgreSQL journey",
            "assetClass": "equipment"
        }),
    );
    let record_identifier = Uuid::parse_str(&created.value.data.record_identifier)
        .expect("BReg returns a canonical UUID record identifier");
    let create_etag = created
        .metadata
        .etag()
        .expect("Create returns a strong Base Registry Engine ETag")
        .clone();
    assert_eq!(
        created.metadata.location(),
        Some(format!("/v1/records/assets/{record_identifier}").as_str())
    );

    let create_replay = client
        .create_record(
            &create,
            &create_request,
            &create_key,
            BRegRecordFormat::Json,
        )
        .await
        .expect("the exact Create replay returns the cached result");
    assert_eq!(create_replay.value, created.value);
    assert_eq!(create_replay.metadata.etag(), Some(&create_etag));
    assert_eq!(
        create_replay.metadata.location(),
        created.metadata.location()
    );

    let patch_request = BRegPatchRequest::builder()
        .test("label", json!("Client PostgreSQL journey"))
        .expect("label is readable under the selected PATCH contract")
        .replace("label", json!("Client PostgreSQL journey revised"))
        .expect("label is writable under the selected PATCH contract")
        .build()
        .expect("PATCH contains a bounded mutation");
    let patch_key = BRegIdempotencyKey::parse("client-pg-patch")
        .expect("fixture PATCH idempotency key is valid");
    let patched = client
        .patch_record(
            &patch,
            record_identifier,
            &create_etag,
            &patch_request,
            &patch_key,
            BRegRecordFormat::Json,
        )
        .await
        .expect("metadata-bound PATCH accepts the returned strong ETag");
    assert_registry_record(
        &patched.value,
        "asset-item",
        "2",
        &json!({
            "assetCode": "CLIENT-PG-001",
            "label": "Client PostgreSQL journey revised",
            "assetClass": "equipment"
        }),
    );
    let patch_etag = patched
        .metadata
        .etag()
        .expect("PATCH returns the next strong Base Registry Engine ETag")
        .clone();
    assert_ne!(patch_etag, create_etag);
    assert!(patched.metadata.location().is_none());

    let patch_replay = client
        .patch_record(
            &patch,
            record_identifier,
            &create_etag,
            &patch_request,
            &patch_key,
            BRegRecordFormat::Json,
        )
        .await
        .expect("the exact PATCH replay returns the cached result despite the consumed ETag");
    assert_eq!(patch_replay.value, patched.value);
    assert_eq!(patch_replay.metadata.etag(), Some(&patch_etag));

    let stale_key = BRegIdempotencyKey::parse("client-pg-patch-stale")
        .expect("fixture stale-write idempotency key is valid");
    let stale = client
        .patch_record(
            &patch,
            record_identifier,
            &create_etag,
            &patch_request,
            &stale_key,
            BRegRecordFormat::Json,
        )
        .await
        .expect_err("a fresh request cannot reuse the stale pre-PATCH ETag");
    assert_eq!(
        stale.status(),
        Some(StatusCode::PRECONDITION_FAILED.as_u16())
    );
    assert_eq!(
        stale.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    assert!(stale.trace_id().is_some());

    let stored = client
        .get_record(
            "assets",
            &record_identifier.to_string(),
            &BRegRecordOptions::default()
                .access_profile("asset-operator")
                .expect("compiled asset profile is a valid client identifier"),
        )
        .await
        .expect("the client reads the final PostgreSQL record state");
    assert_registry_record(
        &stored.value,
        "asset-item",
        "2",
        &json!({
            "assetCode": "CLIENT-PG-001",
            "label": "Client PostgreSQL journey revised",
            "assetClass": "equipment"
        }),
    );
    assert_eq!(
        stored.value.data.record_identifier,
        patched.value.data.record_identifier
    );
    assert_eq!(stored.metadata.etag(), Some(&patch_etag));

    http_server.finish().await;
    harness.finish().await;
}

fn assert_registry_record(
    response: &registry_breg_client::RegistryRecordSingleResponse,
    entity_identifier: &str,
    revision_identifier: &str,
    domain_data: &Value,
) {
    assert!(response.json_ld_context.is_none());
    assert_eq!(
        response.meta.registry_identifier,
        "asset-site-placement-change-requests"
    );
    assert_eq!(
        response.meta.dataset_identifier,
        "asset-site-placement-change-requests"
    );
    assert_eq!(response.meta.entity_type_identifier, entity_identifier);
    assert_eq!(response.data.revision_identifier, revision_identifier);
    assert_eq!(
        serde_json::to_value(&response.data.domain_data)
            .expect("decoded Registry Record data serializes"),
        *domain_data
    );
}

struct SuccessResponse {
    headers: axum::http::HeaderMap,
    document: Value,
}

async fn create_record(
    harness: &PilotHarness,
    route: &str,
    token: &str,
    gold_dataset: &Value,
) -> String {
    let body = json!({"data": gold_dataset["records"][0]["domainData"].clone()});
    let response = harness
        .send_json(
            Method::POST,
            &format!("/v1/records/{route}?accessProfile=fixture-writer"),
            Some(token),
            Some(&format!("seed-{route}")),
            body,
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED, "seed {route}");
    let document = response_json(response).await;
    assert_eq!(
        document["data"]["domainData"],
        gold_dataset["records"][0]["domainData"]
    );
    assert_eq!(
        document["data"]["revisionIdentifier"],
        gold_dataset["records"][0]["revisionIdentifier"]
    );
    document["data"]["recordIdentifier"]
        .as_str()
        .expect("BReg assigns an opaque non-empty record identifier")
        .to_owned()
}

async fn create_additional_record(
    harness: &PilotHarness,
    route: &str,
    token: &str,
    idempotency_key: &str,
    domain_data: Value,
) -> String {
    let response = harness
        .send_json(
            Method::POST,
            &format!("/v1/records/{route}?accessProfile=fixture-writer"),
            Some(token),
            Some(idempotency_key),
            json!({"data": domain_data}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED, "seed {route}");
    response_json(response).await["data"]["recordIdentifier"]
        .as_str()
        .expect("BReg assigns an opaque non-empty record identifier")
        .to_owned()
}

async fn exercise_breg_client(
    base_url: &str,
    first_public_identifier: &str,
    second_public_identifier: &str,
    protected_identifier: &str,
    protected_reader_token: &str,
    public: &Value,
    protected: &Value,
) {
    let anonymous_client = BaseRegistryClient::new(BaseRegistryClientConfig::new(
        base_url.parse().expect("pilot loopback URL parses"),
    ))
    .expect("anonymous Base Registry Engine client config is valid");
    let protected_client = BaseRegistryClient::new(
        BaseRegistryClientConfig::new(base_url.parse().expect("pilot loopback URL parses"))
            .with_token_provider(Arc::new(
                StaticToken::new(protected_reader_token)
                    .expect("MockIdp token is an outbound bearer value"),
            )),
    )
    .expect("protected Base Registry Engine client config is valid");

    let public_openapi = anonymous_client
        .openapi(Some("public-reader"))
        .await
        .expect("anonymous caller receives its filtered OpenAPI");
    let public_openapi: Value = serde_json::from_slice(public_openapi.value.as_bytes())
        .expect("client preserves strict OpenAPI bytes");
    assert!(public_openapi["paths"]
        .get("/v1/records/public-units/{record_id}")
        .is_some());
    assert!(public_openapi.to_string().find("protected-units").is_none());

    let protected_openapi = protected_client
        .openapi(Some("protected-reader"))
        .await
        .expect("authorized caller receives its filtered OpenAPI");
    let protected_openapi: Value = serde_json::from_slice(protected_openapi.value.as_bytes())
        .expect("client preserves strict protected OpenAPI bytes");
    assert!(protected_openapi["paths"]
        .get("/v1/records/protected-units/{record_id}")
        .is_some());
    assert!(protected_openapi["paths"]
        .get("/v1/records/public-units/{record_id}")
        .is_none());

    let public_options = BRegRecordOptions::default()
        .access_profile("public-reader")
        .expect("compiled public profile is a valid client identifier");
    let public_json = anonymous_client
        .get_record("public-units", first_public_identifier, &public_options)
        .await
        .expect("anonymous client decodes one JSON Registry Record");
    assert_eq!(
        public_json.value.data.record_identifier,
        first_public_identifier
    );
    assert_eq!(
        public_json.value.data.domain_data.get("label"),
        public["records"][0]["domainData"].get("label")
    );
    assert!(public_json.metadata.etag().is_some());

    let public_json_ld_options = BRegRecordOptions::default()
        .access_profile("public-reader")
        .expect("compiled public profile is a valid client identifier")
        .format(BRegRecordFormat::JsonLd);
    let public_json_ld = anonymous_client
        .get_record(
            "public-units",
            first_public_identifier,
            &public_json_ld_options,
        )
        .await
        .expect("anonymous client decodes one JSON-LD Registry Record");
    assert!(public_json_ld
        .value
        .json_ld_context
        .as_ref()
        .is_some_and(|context| context.is_shared_only()));

    let first_page = anonymous_client
        .list_records(
            "public-units",
            &BRegListRequest::default()
                .options(public_options)
                .top(1)
                .expect("one is a valid BReg page size"),
        )
        .await
        .expect("anonymous client decodes the first bounded collection page");
    assert_eq!(first_page.value.value.items.len(), 1);
    assert!(first_page.metadata.etag().is_none());
    let continuation = first_page
        .value
        .continuation
        .as_ref()
        .expect("two records with top=1 produce an explicit continuation");
    let second_page = anonymous_client
        .continue_list(continuation)
        .await
        .expect("client advances exactly one opaque BReg continuation");
    assert_eq!(second_page.value.value.items.len(), 1);
    assert!(second_page.value.continuation.is_none());
    let returned_identifiers = first_page
        .value
        .value
        .items
        .iter()
        .chain(second_page.value.value.items.iter())
        .map(|record| record.record_identifier.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        returned_identifiers,
        BTreeSet::from([first_public_identifier, second_public_identifier])
    );

    let protected_options = BRegRecordOptions::default()
        .access_profile("protected-reader")
        .expect("compiled protected profile is a valid client identifier");
    let protected_json = protected_client
        .get_record("protected-units", protected_identifier, &protected_options)
        .await
        .expect("authorized client decodes one protected Registry Record");
    assert_eq!(
        protected_json.value.data.domain_data.get("label"),
        protected["records"][0]["domainData"].get("label")
    );
    let protected_list = protected_client
        .list_records(
            "protected-units",
            &BRegListRequest::default().options(protected_options.clone()),
        )
        .await
        .expect("authorized client decodes the protected collection");
    assert_eq!(protected_list.value.value.items.len(), 1);

    let concealed = anonymous_client
        .get_record("protected-units", protected_identifier, &protected_options)
        .await
        .expect_err("anonymous access to the protected route stays concealed");
    assert_eq!(concealed.status(), Some(StatusCode::NOT_FOUND.as_u16()));
    assert_eq!(
        concealed.problem_code(),
        Some(BRegProblemCode::ResourceNotFound)
    );
}

async fn get_success(
    harness: &PilotHarness,
    uri: &str,
    token: Option<&str>,
    media_type: &str,
) -> SuccessResponse {
    let response = harness
        .send(
            Method::GET,
            uri,
            token,
            &[("accept", media_type)],
            Vec::new(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
    assert_eq!(response.headers()["content-type"], media_type);
    let headers = response.headers().clone();
    let document = response_json(response).await;
    SuccessResponse { headers, document }
}

fn assert_profile_link(headers: &axum::http::HeaderMap) {
    let link = headers["link"].to_str().expect("Link header is UTF-8");
    assert!(link.contains(&format!("<{PROFILE_IDENTIFIER}>; rel=\"profile\"")));
}

fn assert_shared_single(document: &Value, gold: &Value, dataset: &Value, json_ld: bool) {
    let (dataset_identifier, entity_type_identifier) = server_resource_identifiers(dataset);
    assert_eq!(gold["profileIdentifier"], PROFILE_IDENTIFIER);
    assert_eq!(
        document["meta"]["registryIdentifier"],
        BREG_REGISTRY_IDENTIFIER
    );
    assert_eq!(document["meta"]["datasetIdentifier"], dataset_identifier);
    assert_eq!(
        document["meta"]["entityTypeIdentifier"],
        entity_type_identifier
    );
    assert_eq!(
        document["data"]["revisionIdentifier"],
        dataset["records"][0]["revisionIdentifier"]
    );
    assert_eq!(
        document["data"]["domainData"],
        dataset["records"][0]["domainData"]
    );
    assert!(document["data"]["recordIdentifier"]
        .as_str()
        .is_some_and(|identifier| !identifier.is_empty()));
    if json_ld {
        assert_eq!(document["@context"], CONTEXT_IDENTIFIER);
    } else {
        assert!(document.get("@context").is_none());
    }
}

fn assert_shared_collection(document: &Value, gold: &Value, dataset: &Value, json_ld: bool) {
    let (dataset_identifier, entity_type_identifier) = server_resource_identifiers(dataset);
    assert_eq!(gold["profileIdentifier"], PROFILE_IDENTIFIER);
    assert_eq!(
        document["meta"]["registryIdentifier"],
        BREG_REGISTRY_IDENTIFIER
    );
    assert_eq!(document["meta"]["datasetIdentifier"], dataset_identifier);
    assert_eq!(
        document["meta"]["entityTypeIdentifier"],
        entity_type_identifier
    );
    let items = document["items"].as_array().expect("collection items");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["revisionIdentifier"],
        dataset["records"][0]["revisionIdentifier"]
    );
    assert_eq!(items[0]["domainData"], dataset["records"][0]["domainData"]);
    assert!(document["pageInfo"].get("nextCursor").is_some());
    if json_ld {
        assert_eq!(document["@context"], CONTEXT_IDENTIFIER);
    } else {
        assert!(document.get("@context").is_none());
    }
}

fn server_resource_identifiers(dataset: &Value) -> (&'static str, &'static str) {
    match dataset["visibility"].as_str() {
        Some("public") => ("public-units", "public-unit"),
        Some("protected") => ("protected-units", "protected-unit"),
        visibility => panic!("unknown semantic gold visibility {visibility:?}"),
    }
}

async fn assert_concealed_equivalence(
    unauthorized: Response<Body>,
    unknown: Response<Body>,
    protected: &Value,
) {
    assert_eq!(unauthorized.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert!(unauthorized.headers().get("link").is_none());
    assert!(unknown.headers().get("link").is_none());
    let mut unauthorized = json_from_response(unauthorized).await;
    let mut unknown = json_from_response(unknown).await;
    unauthorized
        .as_object_mut()
        .expect("problem object")
        .remove("traceId");
    unknown
        .as_object_mut()
        .expect("problem object")
        .remove("traceId");
    assert_eq!(unauthorized, unknown);
    assert_eq!(unauthorized["code"], "resource.not_found");
    let rendered = unauthorized.to_string();
    assert!(!rendered.contains("protected-units"));
    assert!(!rendered.contains(
        protected["records"][0]["domainData"]["label"]
            .as_str()
            .unwrap()
    ));
}

async fn json_from_response(response: Response<Body>) -> Value {
    serde_json::from_slice(&response_bytes(response).await).expect("response is strict JSON")
}

async fn caller_openapi(harness: &PilotHarness, profile: &str, token: Option<&str>) -> Value {
    let response = harness
        .send(
            Method::GET,
            &format!("/openapi.json?accessProfile={profile}"),
            token,
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

fn validate_exact_responses(
    openapi: &Value,
    path: &str,
    method: &str,
    json_document: &Value,
    json_ld_document: &Value,
) {
    let json_validator = exact_response_validator(openapi, path, method, "application/json");
    let json_ld_validator = exact_response_validator(openapi, path, method, "application/ld+json");
    assert!(json_validator.is_valid(json_document));
    assert!(json_ld_validator.is_valid(json_ld_document));
    assert_meta_constant_mutations_are_rejected(&json_validator, json_document);
}

fn exact_response_validator(
    openapi: &Value,
    path: &str,
    method: &str,
    media_type: &str,
) -> JSONSchema {
    let response =
        openapi["paths"][path][method]["responses"]["200"]["content"][media_type]["schema"].clone();
    assert_eq!(
        openapi["paths"][path][method]["x-registry-responseProfile"],
        PROFILE_IDENTIFIER
    );
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/$defs/response",
        "$defs": {"response": response},
        "components": openapi["components"].clone()
    });
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .expect("exact caller-filtered response schema compiles locally")
}

fn assert_meta_constant_mutations_are_rejected(validator: &JSONSchema, document: &Value) {
    for member in [
        "registryIdentifier",
        "datasetIdentifier",
        "entityTypeIdentifier",
    ] {
        let mut mutated = document.clone();
        mutated["meta"][member] = json!(format!("wrong-{member}"));
        assert!(
            !validator.is_valid(&mutated),
            "exact schema accepted a changed meta.{member} constant"
        );
    }
}

fn shared_base_validator() -> JSONSchema {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../products/registry-record/schema/registry-record-v1.schema.json"
    ))
    .expect("shared Registry Record schema is JSON");
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .expect("shared Registry Record schema compiles locally")
}

fn artifact_json(harness: &PilotHarness, path: &str) -> Value {
    serde_json::from_slice(
        &harness
            .registry
            .artifacts()
            .get(path)
            .unwrap_or_else(|| panic!("artifact {path} exists"))
            .bytes,
    )
    .unwrap_or_else(|error| panic!("artifact {path} is JSON: {error}"))
}

fn semantic_gold() -> Value {
    serde_json::from_str(include_str!(
        "../../../products/registry-record/fixtures/cross-product/semantic-gold.json"
    ))
    .expect("cross-product semantic gold is strict JSON")
}

fn dataset<'a>(gold: &'a Value, visibility: &str) -> &'a Value {
    gold["datasets"]
        .as_array()
        .expect("gold datasets")
        .iter()
        .find(|dataset| dataset["visibility"] == visibility)
        .unwrap_or_else(|| panic!("gold has a {visibility} dataset"))
}
