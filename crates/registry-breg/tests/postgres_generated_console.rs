// SPDX-License-Identifier: Apache-2.0
//! Generated language adapters against the real HTTP service and PostgreSQL RLS.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::api::{VerifiedClaimValue, VerifiedRequestClaims};
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_yaml, ModuleAssetSource};
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegRecordFormat,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

fn claims(scope: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "console-author",
        BTreeSet::from([scope.into()]),
        Some("facility-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
    )
    .unwrap()
}

fn registry() -> registry_breg::CompiledRegistry {
    let mut source = parse_project_yaml(include_bytes!(
        "../../../products/breg/examples/refactor/facility/registry.yaml"
    ))
    .unwrap();
    source.access_profiles.push(serde_json::from_value(json!({"id":"fixture-seeder",
        "principalClaim":"registry_principal","requiredScopes":["fixture:seed"],
        "requiredPurposes":["facility-administration"],"permissions":{"records":[{
            "recordType":"operator","operations":["create","get"],
            "readableFields":["operator-code","status","jurisdiction"],
            "writableFields":["operator-code","status","jurisdiction"],"rowBoundaries":"unrestricted"}]}})).unwrap());
    source.access_profiles.push(serde_json::from_value(json!({"id":"fixture-redacted-reader",
        "principalClaim":"registry_principal","requiredScopes":["fixture:redacted"],
        "requiredPurposes":["facility-administration"],"permissions":{"records":[{
            "recordType":"facility","operations":["get"],"readableFields":["status","jurisdiction"],
            "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}})).unwrap());
    compile_project_with_assets(
        &source,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/correct-address.rhai".into(),
            bytes: include_bytes!(
                "../../../products/breg/examples/refactor/facility/plans/correct-address.rhai"
            )
            .to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
}

struct UnusedReview;
#[async_trait::async_trait]
impl registry_breg::review_store::ReviewResultSource for UnusedReview {
    async fn approved_evidence(
        &self,
        _: &str,
        _: &registry_review_client::ReviewRequestAccepted,
    ) -> Result<
        registry_breg::review_integration::AcceptedReviewEvidence,
        registry_breg::mutation::MutationError,
    > {
        Err(registry_breg::mutation::MutationError::Unavailable)
    }
}
struct NoToken;
#[async_trait::async_trait]
impl registry_platform_httputil::TokenProvider for NoToken {
    async fn bearer_token(
        &self,
    ) -> Result<registry_platform_httputil::BearerToken, registry_platform_httputil::TokenError>
    {
        Err(registry_platform_httputil::TokenError::Unavailable)
    }
}
fn review_authorities() -> std::sync::Arc<registry_breg::review_store::ReviewAuthorityRegistry> {
    use registry_breg::review_store::{ReviewAuthorityClient, ReviewAuthorityRegistry};
    let client = registry_review_client::ReviewClient::new(
        registry_review_client::ReviewClientConfig::new("http://127.0.0.1:9/".parse().unwrap()),
    )
    .unwrap();
    let authority = std::sync::Arc::new(
        ReviewAuthorityClient::new(
            "casework".into(),
            client,
            std::sync::Arc::new(NoToken),
            "console-producer".into(),
            "facility-registry".into(),
            7,
            None,
            None,
        )
        .unwrap(),
    );
    std::sync::Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([("casework".into(), authority)])).unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires generated console JavaScript and prebuilt native Node/Python clients"]
async fn generated_typescript_and_python_consoles_use_live_http_and_rls() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let build =
        std::env::var("BREG_CONSOLE_BUILD").expect("emit checked TypeScript before this test");
    let python_module = std::env::var("BREG_PYTHON_MODULE_ROOT")
        .expect("build the Python extension before this test");
    for language in ["node", "python3"] {
        let fixture = client_http::ClientFixture::start_with_mutations(
            registry(),
            claims("fixture:seed"),
            |mutations| {
                mutations.with_proposal_review_substitute_for_test(
                    review_authorities(),
                    std::sync::Arc::new(UnusedReview),
                )
            },
        )
        .await;
        let seed = fixture
            .http
            .client
            .registry_contract(Some("fixture-seeder"))
            .await
            .unwrap();
        let BRegDirectWrite::Create(create) = seed
            .value
            .select_direct_write("records.operator.create", "fixture-seeder")
            .unwrap()
        else {
            panic!("create grant")
        };
        let operator = fixture
            .http
            .client
            .create_record(
                &create,
                &BRegCreateRequest::new(
                    json!({"operatorCode":"OP-LIVE","status":"active","jurisdiction":"zone-a"})
                        .as_object()
                        .unwrap()
                        .clone(),
                )
                .unwrap(),
                &BRegIdempotencyKey::parse("live-operator").unwrap(),
                BRegRecordFormat::Json,
            )
            .await
            .unwrap()
            .value
            .data
            .record_identifier;
        let registrar = fixture
            .client_for(claims("registry:facility:register"))
            .await;
        let metadata = registrar
            .client
            .registry_contract(Some("facility-registrar"))
            .await
            .unwrap();
        let binding = metadata
            .value
            .select_action("register-facility", "facility-registrar")
            .unwrap();
        let input = json!({"facilityCode":"LIVE-SEED","name":"Live clinic","addressLine":"1 Main Road","city":"Bangkok","postalCode":"10200","operatorId":operator,"jurisdiction":"zone-a"});
        let invocation =
            BRegActionInvocationRequest::new(&binding, input.as_object().unwrap().clone(), None)
                .unwrap();
        let initial = registrar
            .client
            .invoke_action(
                &binding,
                &invocation,
                &BRegIdempotencyKey::parse("live-initial").unwrap(),
            )
            .await
            .unwrap();
        let facility = initial.value.results()["facility"]
            .record_identifier()
            .to_owned();
        let reader = fixture.client_for(claims("registry:facility:read")).await;
        let redacted = fixture.client_for(claims("fixture:redacted")).await;
        let author = fixture
            .client_for(claims("registry:facility:correction:submit"))
            .await;
        let applier = fixture
            .client_for(claims("registry:facility:correction:apply"))
            .await;
        let script = root
            .join("products/breg/examples/refactor/facility/console")
            .join(if language == "node" {
                "live.cjs"
            } else {
                "live.py"
            });
        let mut command = std::process::Command::new(language);
        command
            .arg(script)
            .current_dir(&root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("BREG_CONSOLE_BUILD", &build)
            .env("BREG_PYTHON_MODULE_ROOT", &python_module)
            .env("BREG_READER_URL", &reader.base_url)
            .env("BREG_REDACTED_URL", &redacted.base_url)
            .env("BREG_REGISTRAR_URL", &registrar.base_url)
            .env("BREG_AUTHOR_URL", &author.base_url)
            .env("BREG_APPLIER_URL", &applier.base_url)
            .env("BREG_FACILITY_ID", facility.to_string())
            .env("BREG_OPERATOR_ID", &operator);
        let output = tokio::task::spawn_blocking(move || command.output().unwrap())
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{language} console failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        drop((reader, redacted, registrar, author, applier));
        fixture.finish().await;
    }
}
