// SPDX-License-Identifier: Apache-2.0

//! Starter acceptance cases in the existing PostgreSQL fixture-journey target.
//! Authored normal/security suites execute with their exact synthetic claims;
//! additional real-router requests pin refusals that fixture preflight cannot
//! express, including operations absent from the caller's published grants.

use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use registry_breg::fixtures::ValidatedFixtureJourneys;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use super::{
    compile_project, execute_schema_test, fs, load_package, load_runtime_config,
    measure_compiled_schema_fingerprint, parse_project_yaml, prepare_package,
    prepare_schema_test_database_with_connection_configs_for_test,
    prepare_with_connection_config_for_test, validate_fixture_journeys,
    validate_schema_test_receipt_for_package, write_private, CompileProfile, MockIdp,
    PackageBuildRequest, PackageFixture, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageSourceFile, SchemaTestCredentialBinding,
    SchemaTestCredentialBindings, SignaturePolicy, TestDatabase, Zeroizing, AUDIENCE,
    FIXTURE_JOURNEYS_PATH,
};

struct Starter {
    project: &'static [u8],
    normal: &'static [u8],
    security: &'static [u8],
    first_record: &'static [u8],
    reviewed_change: &'static [u8],
    primary_route: &'static str,
    correction_route: &'static str,
    correction_field: &'static str,
    hidden_reader_fields: &'static [&'static str],
    references: ReferencePolicy,
    expected_journeys: &'static [&'static str],
}

enum ReferencePolicy {
    Organizations,
    AgriculturalHolders,
    NoLocalReferences,
    SeedLots,
}

const ORGANIZATIONS: Starter = Starter {
    project: include_bytes!("../../../../products/breg/starters/public-organizations/core/registry.yaml"),
    normal: include_bytes!("../../../../products/breg/starters/public-organizations/core/tests/journeys.yaml"),
    security: include_bytes!("../../../../products/breg/starters/public-organizations/core/tests/security-journeys.yaml"),
    first_record: include_bytes!("../../../../products/breg/starters/public-organizations/core/examples/inputs/first-record.json"),
    reviewed_change: include_bytes!("../../../../products/breg/starters/public-organizations/core/examples/inputs/reviewed-change.json"),
    primary_route: "public-organizations",
    correction_route: "name-corrections",
    correction_field: "name",
    hidden_reader_fields: &[],
    references: ReferencePolicy::Organizations,
    expected_journeys: &["relationship-correction", "starter-model-policy"],
};
const AGRICULTURE: Starter = Starter {
    project: include_bytes!("../../../../products/breg/starters/agricultural-holdings/core/registry.yaml"),
    normal: include_bytes!("../../../../products/breg/starters/agricultural-holdings/core/tests/journeys.yaml"),
    security: include_bytes!("../../../../products/breg/starters/agricultural-holdings/core/tests/security-journeys.yaml"),
    first_record: include_bytes!("../../../../products/breg/starters/agricultural-holdings/core/examples/inputs/first-record.json"),
    reviewed_change: include_bytes!("../../../../products/breg/starters/agricultural-holdings/core/examples/inputs/reviewed-change.json"),
    primary_route: "farms",
    correction_route: "name-corrections",
    correction_field: "name",
    hidden_reader_fields: &[],
    references: ReferencePolicy::AgriculturalHolders,
    expected_journeys: &["starter-model-policy"],
};
const PROFESSIONAL_LICENCES: Starter = Starter {
    project: include_bytes!("../../../../products/breg/starters/professional-licences/core/registry.yaml"),
    normal: include_bytes!("../../../../products/breg/starters/professional-licences/core/tests/journeys.yaml"),
    security: include_bytes!("../../../../products/breg/starters/professional-licences/core/tests/security-journeys.yaml"),
    first_record: include_bytes!("../../../../products/breg/starters/professional-licences/core/examples/inputs/first-record.json"),
    reviewed_change: include_bytes!("../../../../products/breg/starters/professional-licences/core/examples/inputs/reviewed-change.json"),
    primary_route: "professional-licenses",
    correction_route: "scope-corrections",
    correction_field: "authorizationConditions",
    hidden_reader_fields: &["localIdentifier", "personReference", "regulatorReference", "licensedActivities", "authorizationConditions"],
    references: ReferencePolicy::NoLocalReferences,
    expected_journeys: &["starter-model-policy"],
};

const SEED_LOTS: Starter = Starter {
    project: include_bytes!("../../../../products/breg/starters/seed-lots/core/registry.yaml"),
    normal: include_bytes!("../../../../products/breg/starters/seed-lots/core/tests/journeys.yaml"),
    security: include_bytes!(
        "../../../../products/breg/starters/seed-lots/core/tests/security-journeys.yaml"
    ),
    first_record: include_bytes!(
        "../../../../products/breg/starters/seed-lots/core/examples/inputs/first-record.json"
    ),
    reviewed_change: include_bytes!(
        "../../../../products/breg/starters/seed-lots/core/examples/inputs/reviewed-change.json"
    ),
    primary_route: "seed-lots",
    correction_route: "lot-number-corrections",
    correction_field: "lotNumber",
    hidden_reader_fields: &[],
    references: ReferencePolicy::SeedLots,
    expected_journeys: &["starter-model-policy"],
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seed_lot_starter_policy_journeys_and_http_refusals() {
    run_starter(&SEED_LOTS).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_organization_starter_policy_journeys_and_http_refusals() {
    run_starter(&ORGANIZATIONS).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agricultural_starter_policy_journeys_and_http_refusals() {
    run_starter(&AGRICULTURE).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn professional_licence_starter_policy_journeys_and_http_refusals() {
    run_starter(&PROFESSIONAL_LICENCES).await;
}

async fn run_starter(starter: &Starter) {
    let project = parse_project_yaml(starter.project).expect("authored starter parses");
    let registry = compile_project(&project, &[], CompileProfile::Production)
        .expect("authored starter compiles without policy substitutions");
    let fingerprint = measure_compiled_schema_fingerprint(&registry).await;
    let idp = MockIdp::start().await;
    for (name, bytes) in [("normal", starter.normal), ("security", starter.security)] {
        let suite = validate_fixture_journeys(bytes, &registry).expect("starter suite preflights");
        let package = starter_package(starter.project, bytes, &fingerprint);
        let database = TestDatabase::create(8).await;
        let config_path = starter_runtime_config(&package, &database, &idp);
        let config = load_runtime_config(&config_path).expect("starter runtime config loads");
        let prepared_database = prepare_schema_test_database_with_connection_configs_for_test(
            &config,
            &package.prepared,
            &database.migration_config,
            &database.runtime_config,
        )
        .await
        .expect("native schema-test prepares the isolated database");
        let receipt = execute_schema_test(
            prepared_database,
            &config,
            &package.prepared,
            &suite,
            authored_credentials(bytes, &suite, &idp),
        )
        .await
        .unwrap_or_else(|error| {
            panic!("{} {name} PostgreSQL suite: {error}", starter.primary_route)
        });
        assert_eq!(receipt.successful_journey_ids(), starter.expected_journeys);
        validate_schema_test_receipt_for_package(
            &receipt.canonical_bytes().expect("receipt encodes"),
            &package.prepared,
            &suite,
        )
        .expect("receipt binds the exact authored source and journey bytes");

        if name == "normal" {
            let server = prepare_with_connection_config_for_test(
                &config_path,
                database.runtime_config.clone(),
            )
            .await
            .expect("verified package startup constructs the real authenticated router");
            let http = StarterHttp {
                app: server.app(),
                idp: &idp,
            };
            assert_http_policy(starter, &http).await;
            drop(server);
        }
        database.cleanup().await;
    }
    idp.stop().await;
}

fn starter_package(project: &[u8], journeys: &[u8], fingerprint: &str) -> PackageFixture {
    let source = parse_project_yaml(project).expect("starter project parses");
    let identity = source.package.expect("starter declares package identity");
    let prepared = prepare_package(PackageBuildRequest {
        environment: identity.environment.clone(),
        instance_id: identity.instance_id.clone(),
        database_id: "starter-policy-database".to_owned(),
        sequence: identity.sequence,
        prior_revision: None,
        compiler_source_revision: identity.source_revision.clone(),
        schema_fingerprint: fingerprint.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "sources/project.yaml".to_owned(),
            bytes: project.to_vec(),
        },
        modules: Vec::new(),
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.to_owned(),
            bytes: journeys.to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
    .expect("exact local starter package prepares");
    let migration_plan = prepared.file_bytes()["database/migration-plan.json"].clone();
    let root = tempfile::tempdir().expect("private fixture directory creates");
    let directory = root
        .path()
        .canonicalize()
        .expect("fixture directory canonicalizes");
    let package_root = directory.join("package");
    let revision = prepared.package_revision().to_owned();
    prepared
        .publish_to_directory(&package_root, Vec::new())
        .expect("local package publishes");
    let anchor = directory.join("trust-anchor.json");
    let package = load_package(
        &package_root,
        &PackageLoadContext {
            environment: &identity.environment,
            instance_id: &identity.instance_id,
            database_id: "starter-policy-database",
            database_initialization_environment: &identity.environment,
            compiler_source_revision: &identity.source_revision,
            trust_anchor: None,
            intent: PackageIntent::InitialActivation,
        },
    )
    .expect("package closure rederives without manufactured execution authority");
    PackageFixture {
        _root: root,
        directory,
        package_root,
        anchor,
        revision,
        prepared,
        package,
        project: project.to_vec(),
        migration_plan,
    }
}

fn starter_runtime_config(
    package: &PackageFixture,
    database: &TestDatabase,
    idp: &MockIdp,
) -> std::path::PathBuf {
    // Reuse this target's static-JWKS, bounded-pool, private-secret setup. Only
    // replace deployment identity with the actual authored local package.
    let path = package.write_spatial_runtime_config(database, idp);
    let mut config: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
    let manifest = package.prepared.manifest();
    config["identity"]["environment"] = json!(manifest.environment);
    config["identity"]["databaseInitializationEnvironment"] = json!(manifest.environment);
    config["identity"]["instanceId"] = json!(manifest.instance_id);
    config["identity"]["databaseId"] = json!(manifest.database_id);
    config["package"]["compilerSourceRevision"] = json!(manifest.compiler.source_revision);
    write_private(&path, serde_norway::to_string(&config).unwrap().as_bytes());
    path
}

fn authored_credentials(
    bytes: &[u8],
    suite: &ValidatedFixtureJourneys,
    idp: &MockIdp,
) -> SchemaTestCredentialBindings {
    let source: Value = serde_norway::from_slice(bytes).expect("authored journeys parse");
    let mut bindings = Vec::new();
    for journey in source["journeys"].as_array().unwrap() {
        for step in journey["steps"].as_array().unwrap() {
            let claims = &step["claims"];
            let scopes = claims["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>()
                .join(" ");
            let token = idp.mint_token(json!({
                "aud": AUDIENCE,
                "registry_principal": claims["principal"],
                "registry_purpose": claims["purpose"],
                "scope": scopes,
            }));
            bindings.push(SchemaTestCredentialBinding::bearer(
                journey["id"].as_str().unwrap(),
                step["id"].as_str().unwrap(),
                Zeroizing::new(token),
            ));
        }
    }
    SchemaTestCredentialBindings::new(suite, bindings)
        .expect("every exact authored actor binds once")
}

struct Actor<'a> {
    principal: &'a str,
    scope: &'a str,
}

struct StarterHttp<'a> {
    app: Router,
    idp: &'a MockIdp,
}

impl StarterHttp<'_> {
    async fn request(
        &self,
        method: &str,
        path: &str,
        profile: &str,
        actor: Actor<'_>,
        body: Option<Value>,
        extra_headers: &[(&str, &str)],
    ) -> (StatusCode, Value, HeaderMap) {
        let token = self.idp.mint_token(json!({"aud": AUDIENCE, "registry_principal": actor.principal, "registry_purpose": "starter-learning", "scope": actor.scope}));
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{path}?accessProfile={profile}"))
            .header("authorization", format!("Bearer {token}"))
            .header("accept", "application/json");
        if method != "GET"
            && !extra_headers
                .iter()
                .any(|(name, _)| *name == "idempotency-key")
        {
            request = request.header("idempotency-key", Uuid::new_v4().to_string());
        }
        if body.is_some()
            && !extra_headers
                .iter()
                .any(|(name, _)| *name == "content-type")
        {
            request = request.header("content-type", "application/json");
        }
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
        }
        let request = request
            .body(Body::from(
                body.map(|value| serde_json::to_vec(&value).unwrap())
                    .unwrap_or_default(),
            ))
            .unwrap();
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("real router responds");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .expect("bounded response");
        (
            status,
            serde_json::from_slice(&bytes).expect("response is JSON"),
            headers,
        )
    }

    async fn persona(
        &self,
        method: &str,
        path: &str,
        profile: &str,
        data: Option<Value>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Value, HeaderMap) {
        self.request(
            method,
            path,
            profile,
            Actor {
                principal: &format!("synthetic-{profile}"),
                scope: &format!("starter:{profile}"),
            },
            data,
            headers,
        )
        .await
    }

    async fn create(&self, route: &str, data: Value) -> String {
        let (status, body, _) = self
            .persona(
                "POST",
                &format!("/v1/records/{route}"),
                "editor",
                Some(json!({"data": data})),
                &[],
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "editor can create {route}");
        body["data"]["recordIdentifier"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

async fn selected_action(
    http: &StarterHttp<'_>,
    path: &str,
    profile: &str,
    operation: &str,
) -> Value {
    let (status, body, _) = http.persona("GET", path, profile, None, &[]).await;
    assert_eq!(status, StatusCode::OK);
    body["data"]["request"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["operation"] == operation)
        .expect("configured action is available")
        .clone()
}

async fn send_selected_action(
    http: &StarterHttp<'_>,
    profile: &str,
    action: &Value,
) -> (StatusCode, Value, HeaderMap) {
    let payload = if action["operation"] == "submit_request" {
        json!({})
    } else {
        json!({"proposalVersion": action["proposalVersion"], "effectDigest": action["effectDigest"]})
    };
    http.persona(
        "POST",
        action["href"].as_str().unwrap().split('?').next().unwrap(),
        profile,
        Some(payload),
        &[("if-match", action["ifMatch"].as_str().unwrap())],
    )
    .await
}

async fn invoke_action(http: &StarterHttp<'_>, path: &str, profile: &str, operation: &str) {
    let action = selected_action(http, path, profile, operation).await;
    let (status, body, _) = send_selected_action(http, profile, &action).await;
    assert_eq!(status, StatusCode::OK, "{operation}: {body}");
}

fn assert_concealed(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "resource.not_found");
}

async fn assert_http_policy(starter: &Starter, http: &StarterHttp<'_>) {
    let first: Value =
        serde_json::from_slice(starter.first_record).expect("first-record input parses");
    let mut first = first["record"].clone();
    first["localIdentifier"] = json!("HTTP-POLICY-TARGET");
    if matches!(starter.references, ReferencePolicy::SeedLots) {
        first["lotNumber"] = json!("HTTP-POLICY-LOT");
    }
    let original_value = first[starter.correction_field].clone();
    assert!(
        !original_value.is_null(),
        "first-record input includes the corrected field"
    );
    let original_record = first.clone();
    let target = http.create(starter.primary_route, first.clone()).await;
    let target_path = format!("/v1/records/{}/{target}", starter.primary_route);
    let (status, _, headers) = http.persona("GET", &target_path, "editor", None, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let change: Value =
        serde_json::from_slice(starter.reviewed_change).expect("reviewed-change input parses");
    let mut change = change["change"].clone();
    change["record"] = json!(target);
    if matches!(starter.references, ReferencePolicy::SeedLots) {
        change["lotNumber"] = json!("HTTP-POLICY-CORRECTED-LOT");
    }
    let (status, body, _) = http.persona("PATCH", &target_path, "editor",
        Some(json!([{"op": "replace", "path": format!("/data/{}", starter.correction_field), "value": change[starter.correction_field]}])),
        &[("content-type", "application/json-patch+json"), ("if-match", headers["etag"].to_str().unwrap())],
    ).await;
    assert_concealed(status, &body);
    first["localIdentifier"] = json!("HTTP-POLICY-REFUSED");
    let (status, body, _) = http
        .request(
            "POST",
            &format!("/v1/records/{}", starter.primary_route),
            "editor",
            Actor {
                principal: "synthetic-reader",
                scope: "starter:reader",
            },
            Some(json!({"data":first})),
            &[],
        )
        .await;
    assert_concealed(status, &body);
    let (status, body, _) = http.persona("GET", &target_path, "editor", None, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["data"]["domainData"][starter.correction_field], original_value,
        "refused direct PATCH leaves the record unchanged"
    );
    let (status, body, _) = http.persona("GET", &target_path, "reader", None, &[]).await;
    assert_eq!(status, StatusCode::OK);
    for field in starter.hidden_reader_fields {
        assert!(
            body["data"]["domainData"].get(*field).is_none(),
            "reader must not receive {field}"
        );
    }
    let draft = http.create(starter.correction_route, change.clone()).await;
    let request_path = format!("/v1/records/{}/{draft}", starter.correction_route);
    let (status, body, _) = http
        .persona("GET", &request_path, "editor", None, &[])
        .await;
    assert_eq!(status, StatusCode::OK);
    let submit = body["data"]["request"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["operation"] == "submit_request")
        .unwrap();
    let submit_path = submit["href"].as_str().unwrap().split('?').next().unwrap();
    let (status, _, _) = http
        .persona(
            "POST",
            submit_path,
            "editor",
            Some(json!({})),
            &[("if-match", submit["ifMatch"].as_str().unwrap())],
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Same principal, same reviewer scope and purpose, fresh actor-specific
    // response: this proves submitter exclusion, not a foreign ETag mismatch.
    let (status, own, _) = http
        .request(
            "GET",
            &request_path,
            "reviewer",
            Actor {
                principal: "synthetic-editor",
                scope: "starter:reviewer",
            },
            None,
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        own["data"]["request"]
            .get("actions")
            .and_then(Value::as_array)
            .is_none_or(|actions| actions
                .iter()
                .all(|action| action["operation"] != "approve_request")),
        "submitter must not be offered approval even with reviewer scopes"
    );
    let (status, independent, _) = http
        .persona("GET", &request_path, "reviewer", None, &[])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        independent["data"]["request"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action["operation"] == "approve_request"),
        "independent reviewer receives the approval action"
    );
    // A submitted request offers no apply authority. Sending the review
    // precondition to the configured apply route must not change the target.
    let request = &independent["data"]["request"];
    assert!(request["actions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|action| action["operation"] != "apply_request"));
    let approve = request["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["operation"] == "approve_request")
        .unwrap();
    let (status, problem, _) = http.persona(
        "POST", &format!("{request_path}/actions/apply"), "reviewer",
        Some(json!({"proposalVersion": request["proposalVersion"], "effectDigest": request["effectDigest"]})),
        &[("if-match", approve["ifMatch"].as_str().unwrap())],
    ).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(problem["code"], "precondition.failed");
    let (_, unchanged, _) = http.persona("GET", &target_path, "editor", None, &[]).await;
    assert_eq!(
        unchanged["data"]["domainData"][starter.correction_field],
        original_value
    );

    // Freeze two independently approved corrections against the same target
    // revision. Applying the first changes only the target, not the second
    // request's ETag: the second refusal must be the target conflict itself.
    if starter.primary_route == "professional-licenses" {
        for activities in [
            json!([]),
            json!(["unknown"]),
            json!([
                "example-general-nursing-care",
                "example-general-nursing-care"
            ]),
            json!(["example-general-nursing-care", "example-engineering-design"]),
        ] {
            let mut invalid = change.clone();
            invalid["licensedActivities"] = activities;
            let (status, body, _) = http
                .persona(
                    "POST",
                    "/v1/records/scope-corrections",
                    "editor",
                    Some(json!({"data":invalid})),
                    &[],
                )
                .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "invalid correction: {body}"
            );
        }
        for (route, input) in [
            ("scope-corrections", &change),
            ("professional-licenses", &original_record),
        ] {
            for field in ["licensedActivities", "authorizationConditions"] {
                for missing in [false, true] {
                    let mut invalid = input.clone();
                    if missing {
                        invalid.as_object_mut().unwrap().remove(field);
                    } else {
                        invalid[field] = Value::Null;
                    }
                    let (status, body, _) = http
                        .persona(
                            "POST",
                            &format!("/v1/records/{route}"),
                            "editor",
                            Some(json!({"data":invalid})),
                            &[],
                        )
                        .await;
                    assert_eq!(status, StatusCode::BAD_REQUEST, "invalid {field}: {body}");
                }
            }
        }
    }
    let second = http.create(starter.correction_route, change.clone()).await;
    let second_path = format!("/v1/records/{}/{second}", starter.correction_route);
    invoke_action(http, &second_path, "editor", "submit_request").await;
    invoke_action(http, &request_path, "reviewer", "approve_request").await;
    invoke_action(http, &second_path, "reviewer", "approve_request").await;
    let second_apply = selected_action(http, &second_path, "reviewer", "apply_request").await;
    invoke_action(http, &request_path, "reviewer", "apply_request").await;
    let unchanged_action = selected_action(http, &second_path, "reviewer", "apply_request").await;
    assert_eq!(
        second_apply, unchanged_action,
        "target mutation does not stale the request action itself"
    );
    let (status, problem, _) = send_selected_action(http, "reviewer", &second_apply).await;
    assert_eq!(
        status,
        StatusCode::PRECONDITION_FAILED,
        "stale target must refuse despite an unchanged request action precondition"
    );
    assert_eq!(problem["code"], "precondition.failed");
    let (_, changed, _) = http.persona("GET", &target_path, "editor", None, &[]).await;
    assert_eq!(
        changed["data"]["domainData"][starter.correction_field],
        change[starter.correction_field]
    );
    if starter.primary_route == "professional-licenses" {
        let mut expected = original_record.clone();
        expected["licensedActivities"] = change["licensedActivities"].clone();
        expected["authorizationConditions"] = json!("");
        assert_eq!(changed["data"]["domainData"], expected,
            "one reviewed application changes exactly activities and conditions, including explicit clearing");
    }
    let (status, history, _) = http
        .persona(
            "GET",
            &format!("{target_path}/revisions"),
            "editor",
            None,
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        history["items"].as_array().unwrap().len(),
        2,
        "only creation and the first approved correction may commit"
    );

    if starter.primary_route == "professional-licenses" {
        let rebase = selected_action(http, &second_path, "editor", "revise_request").await;
        let (status, body, _) = http
            .persona(
                "POST",
                rebase["href"].as_str().unwrap().split('?').next().unwrap(),
                "editor",
                Some(json!({"rebase":true})),
                &[("if-match", rebase["ifMatch"].as_str().unwrap())],
            )
            .await;
        assert_eq!(status, StatusCode::OK, "rebase: {body}");
        let (_, rebased, _) = http.persona("GET", &second_path, "editor", None, &[]).await;
        assert_eq!(rebased["data"]["request"]["bregState"], "draft");
        let (status, _, _) = send_selected_action(http, "reviewer", &second_apply).await;
        assert_eq!(
            status,
            StatusCode::PRECONDITION_FAILED,
            "old frozen application remains stale after rebase"
        );
        invoke_action(http, &second_path, "editor", "submit_request").await;
        invoke_action(http, &second_path, "reviewer", "approve_request").await;
        let apply = selected_action(http, &second_path, "reviewer", "apply_request").await;
        let payload = json!({"proposalVersion":apply["proposalVersion"],"effectDigest":apply["effectDigest"]});
        let apply_path = apply["href"].as_str().unwrap().split('?').next().unwrap();
        let headers = [
            ("if-match", apply["ifMatch"].as_str().unwrap()),
            ("idempotency-key", "nursing-rebased-apply"),
        ];
        let (status, applied, _) = http
            .persona(
                "POST",
                apply_path,
                "reviewer",
                Some(payload.clone()),
                &headers,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "reapproved application: {applied}");
        let (status, replayed, _) = http
            .persona("POST", apply_path, "reviewer", Some(payload), &headers)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            replayed, applied,
            "exact retry returns the same frozen receipt"
        );
        let (_, history, _) = http
            .persona(
                "GET",
                &format!("{target_path}/revisions"),
                "editor",
                None,
                &[],
            )
            .await;
        assert_eq!(
            history["items"].as_array().unwrap().len(),
            3,
            "exact retry adds no target revision"
        );
    }

    let (status, body, _) = http
        .persona("GET", &request_path, "reader", None, &[])
        .await;
    assert_concealed(status, &body);

    match starter.references {
        ReferencePolicy::AgriculturalHolders => {
            assert_agricultural_privacy_and_reference_types(http, &target).await
        }
        ReferencePolicy::Organizations => {
            let other = http.create("public-organizations", json!({"localIdentifier":"HTTP-POLICY-OTHER","name":"Synthetic second organization"})).await;
            http.create("institutional-relationships", json!({"institutionFrom":target,"institutionTo":other,"relationshipType":"reports-to","startDate":"2026-01-01"})).await;
            let (status, body, _) = http.persona("POST", "/v1/records/institutional-relationships", "editor", Some(json!({"data":{"institutionFrom":draft,"institutionTo":other,"relationshipType":"reports-to","startDate":"2026-01-01"}})), &[]).await;
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "request UUID cannot substitute an organization endpoint"
            );
            assert_eq!(body["code"], "mutation.conflict");
        }
        ReferencePolicy::SeedLots => {
            let variety = http.create("plant-varieties", json!({"localIdentifier":"HTTP-POLICY-VARIETY","varietyDenomination":"Synthetic variety"})).await;
            http.create("seed-lots", json!({"localIdentifier":"HTTP-POLICY-DERIVED","lotNumber":"HTTP-DERIVED","quantityKg":"25.000","variety":variety,"sourceLot":target})).await;
            for (field, wrong_id) in [("variety", &target), ("sourceLot", &variety)] {
                let (status, body, _) = http.persona("POST", "/v1/records/seed-lots", "editor", Some(json!({"data":{"localIdentifier":format!("HTTP-WRONG-{field}"),"lotNumber":format!("HTTP-WRONG-{field}"),"quantityKg":"25.000",field:wrong_id}})), &[]).await;
                assert_eq!(
                    status,
                    StatusCode::CONFLICT,
                    "wrong entity cannot substitute {field}"
                );
                assert_eq!(body["code"], "mutation.conflict");
            }
        }
        ReferencePolicy::NoLocalReferences => {}
    }
}

async fn assert_agricultural_privacy_and_reference_types(http: &StarterHttp<'_>, farm: &str) {
    let mut protected = Vec::new();
    for (route, role, field) in [
        (
            "persons",
            "person-holding-operator-roles",
            "holdingOperatorPerson",
        ),
        (
            "organizations",
            "organization-holding-operator-roles",
            "holdingOperatorOrganization",
        ),
        (
            "informal-groups",
            "group-holding-operator-roles",
            "holdingOperatorGroup",
        ),
    ] {
        let holder = http.create(route, json!({"localIdentifier":format!("HTTP-POLICY-{route}"),"name":format!("Synthetic {route}")})).await;
        let role_id = http
            .create(role, json!({"operatedHolding":farm,field:holder}))
            .await;
        protected.push((route, holder));
        protected.push((role, role_id));
        let (status, body, _) = http
            .persona(
                "POST",
                &format!("/v1/records/{role}"),
                "editor",
                Some(json!({"data":{"operatedHolding":farm,field:farm}})),
                &[],
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "Farm UUID is not a {field} reference"
        );
        assert_eq!(body["code"], "mutation.conflict");
    }
    for (route, id) in protected {
        for path in [
            format!("/v1/records/{route}"),
            format!("/v1/records/{route}/{id}"),
        ] {
            let (status, body, _) = http.persona("GET", &path, "reader", None, &[]).await;
            assert_concealed(status, &body);
        }
    }
}
