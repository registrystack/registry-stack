// SPDX-License-Identifier: Apache-2.0
//! Native BReg Proposal to Casework review over both public HTTP contracts.
#![cfg(feature = "postgres-test")]
#[path = "../../registry-breg/tests/support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "../../registry-breg/tests/support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::Router;
use registry_breg::{
    api::{authenticated_router, VerifiedClaimValue, VerifiedRequestClaims},
    auth::{AuthorityClaimConfig, RegistryAuthenticator},
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource},
    mutation::MutationError,
    review_store::{ReviewAuthorityClient, ReviewAuthorityRegistry, ReviewResultSource},
};
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegProposalState, BRegRecordFormat, BaseRegistryClient, BaseRegistryClientConfig, BearerToken,
};
use registry_casework::{
    router as casework_router, CaseworkAuthenticator, CaseworkService, DatabaseConfig, HttpState,
    HumanIdentityConfig, PostgresStore,
};
use registry_casework_breg::{
    BregContextExport, BregContextProvider, DESCRIPTION_API_VERSION, DESCRIPTION_KIND,
};
use registry_casework_core::{
    CaseworkProject, ContentDigest, ReviewContextContract, ReviewContextProvider,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_httputil::{
    BearerToken as HttpBearerToken, StaticToken, TokenError, TokenProvider,
};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use registry_review_client::{ReviewAuth, ReviewClient, ReviewResultResponse, ReviewResultStatus};
use reqwest::{StatusCode, Url};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};
use tokio::net::TcpListener;
use uuid::Uuid;

const BREG_AUDIENCE: &str = "urn:casework:facility-breg";
const CASEWORK_AUDIENCE: &str = "urn:casework:facility-review";
const SOURCE: &str = "facility-registry";

#[allow(
    clippy::disallowed_methods,
    reason = "This maintained fixture is mutated before it enters the owning BReg parser."
)]
fn canonical_source() -> Value {
    serde_norway::from_str(include_str!(
        "../../../products/breg/examples/facility/registry.yaml"
    ))
    .unwrap()
}
fn compile(source: &Value) -> registry_breg::CompiledRegistry {
    let yaml = serde_norway::to_string(source).unwrap();
    let mut authored = parse_project_yaml(yaml.as_bytes()).unwrap();
    authored.access_profiles.push(serde_json::from_value(json!({
        "id":"fixture-seeder","principalClaim":"registry_principal","requiredScopes":["fixture:seed"],
        "requiredPurposes":["facility-administration"],"permissions":{"records":[{
            "recordType":"operator","operations":["create","get"],
            "readableFields":["operator-code","status","jurisdiction"],
            "writableFields":["operator-code","status","jurisdiction"],
            "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
        }]}
    })).unwrap());
    compile_project_with_assets(
        &authored,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/correct-address.rhai".into(),
            bytes: include_bytes!(
                "../../../products/breg/examples/facility/plans/correct-address.rhai"
            )
            .to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
}
fn export(registry: &registry_breg::CompiledRegistry) -> BregContextExport {
    let artifacts = registry.artifacts();
    let index: Value = serde_json::from_slice(
        &artifacts
            .get("generated/review-context-schemas/index.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let entry = &index["correct-address"];
    let path = entry["path"].as_str().unwrap();
    let schema_bytes = String::from_utf8(artifacts.get(path).unwrap().bytes.clone()).unwrap();
    let schema: Value = serde_json::from_str(&schema_bytes).unwrap();
    let result = BregContextExport {
        api_version: DESCRIPTION_API_VERSION.into(),
        kind: DESCRIPTION_KIND.into(),
        source_namespace: SOURCE.into(),
        action_id: "correct-address".into(),
        context_id: schema["x-registry-review-context"]["contextId"]
            .as_str()
            .unwrap()
            .into(),
        contract: ReviewContextContract {
            id: entry["id"].as_str().unwrap().into(),
            revision: ContentDigest::parse(entry["revision"].as_str().unwrap()).unwrap(),
            schema_digest: ContentDigest::parse(entry["digest"].as_str().unwrap()).unwrap(),
        },
        schema,
        schema_bytes,
    };
    result.check().unwrap();
    result
}
fn project(root: &std::path::Path, idp: &MockIdp, context: &BregContextExport) -> CaseworkProject {
    fs::create_dir(root.join("schemas")).unwrap();
    fs::write(
        root.join("schemas/address.schema.json"),
        &context.schema_bytes,
    )
    .unwrap();
    let policy = json!({
        "apiVersion":"id.registrystack.org/formats/casework/project/v1alpha1","kind":"CaseworkProject",
        "project":{"id":"facility-review-journey","version":"1"},
        "accessProfiles":{
            "staff":{"principalClaim":"sub","requiredScopes":["casework:staff"],"role":"staff"},
            "supervisor":{"principalClaim":"sub","requiredScopes":["casework:supervisor"],"role":"supervisor"},
            "administrator":{"principalClaim":"sub","requiredScopes":["casework:admin"],"role":"administrator"},
            "requester":{"principalClaim":"sub","requiredScopes":["casework:reviews:request"],"role":"requester"}
        },
        "queues":{"review":{"label":"Facility reviews"}},
        "teams":{"reviewers":{"label":"Reviewers","serves":["review"],"memberProfiles":["staff"],"supervisorProfiles":["supervisor"]}},
        "contextProviders":{"facility":{"deploymentRef":"facility","sourceNamespace":SOURCE,
            "capabilities":["human-display","service-status"],"serviceProfiles":{"service-status":"casework-review-status"}}},
        "reviewPolicies":{"facility-address-review":{"version":"1","purpose":"approval",
            "context":{"mode":"current-source","provider":"facility","contract":context.contract},
            "stages":[
                {"id":"review","queue":"review","decidingProfiles":["staff"],"requiredApprovals":1,"excludeInitiator":true},
                {"id":"approval","queue":"review","decidingProfiles":["supervisor"],"requiredApprovals":1,"excludePreviousStageReviewers":true}
            ],
            "retention":{"terminalRetentionDays":30,"accountabilityRetentionDays":90},
            "displaySchema":{"$ref":"schemas/address.schema.json"},"outcomes":{"approved":{"label":"Approve","settlement":"approved","reasonRequired":false,"publicReason":"optional"},
                "rejected":{"label":"Reject","settlement":"rejected","reasonRequired":true,"publicReason":"required"}}}},
        "trustedProducers":{"facility-registry":{"profile":"requester","issuer":idp.issuer(),
            "subject":"facility-review-producer","trustedInitiatorIssuer":idp.issuer(),
            "sourceNamespaces":[SOURCE],"reviewPolicies":["facility-address-review"],"retention":{"receiptRetentionDays":7}}}
    });
    fs::write(
        root.join("casework.yaml"),
        serde_norway::to_string(&policy).unwrap(),
    )
    .unwrap();
    let project = CaseworkProject::load(root.join("casework.yaml")).unwrap();
    project.check().unwrap();
    project
}
fn claims(scope: &str, purpose: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "facility-author",
        BTreeSet::from([scope.into()]),
        Some(purpose.into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
    )
    .unwrap()
}
fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}
fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}
struct NoToken;
#[async_trait::async_trait]
impl TokenProvider for NoToken {
    async fn bearer_token(&self) -> Result<HttpBearerToken, TokenError> {
        Err(TokenError::Unavailable)
    }
}
#[derive(Default)]
struct LiveApproval {
    casework: OnceLock<(ReviewClient, HttpBearerToken)>,
}
#[async_trait::async_trait]
impl ReviewResultSource for LiveApproval {
    async fn approved_evidence(
        &self,
        authority: &str,
        accepted: &registry_review_client::ReviewRequestAccepted,
    ) -> Result<registry_breg::review_integration::AcceptedReviewEvidence, MutationError> {
        let (client, token) = self.casework.get().ok_or(MutationError::Unavailable)?;
        let ReviewResultResponse::Available(result) = client
            .result(ReviewAuth::new(token, "requester"), accepted)
            .await
            .map_err(|_| MutationError::Unavailable)?
        else {
            return Err(MutationError::PreconditionFailed);
        };
        registry_breg::review_integration::AcceptedReviewEvidence::from_protocol(
            authority,
            accepted,
            &result.value,
        )
        .map_err(|_| MutationError::PreconditionFailed)
    }
}
fn review_binding() -> Arc<ReviewAuthorityRegistry> {
    let client = ReviewClient::new(registry_review_client::ReviewClientConfig::new(
        "http://127.0.0.1:9/".parse().unwrap(),
    ))
    .unwrap();
    let authority = Arc::new(
        ReviewAuthorityClient::new(
            "casework".into(),
            client,
            Arc::new(NoToken),
            "facility-address-review".into(),
            "facility-registry".into(),
            7,
            None,
            None,
        )
        .unwrap(),
    );
    Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([("casework".into(), authority)])).unwrap(),
    )
}
async fn serve(app: Router) -> (Url, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, task)
}
async fn casework_store() -> (PostgresStore, tokio_postgres::Client, String) {
    let base =
        std::env::var("CASEWORK_REVIEW_TEST_DATABASE_URL").expect("disposable Casework database");
    let schema = format!("breg_casework_{}", Uuid::new_v4().simple());
    let (admin, task) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { task.await.unwrap() });
    admin
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let name = format!("CASEWORK_BREG_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&name, url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp").unwrap();
    let config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{name}"),
        migration_url_ref: format!("secret:env/{name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let store = PostgresStore::connect_migration(&config, &secrets)
        .unwrap()
        .with_audit(registry_casework::CaseworkAudit::capture().0);
    store.migrate().await.unwrap();
    std::env::remove_var(name);
    (store, admin, schema)
}
async fn start_proposal(
    fixture: &client_http::ClientFixture,
    breg_url: &Url,
    idp: &MockIdp,
    index: u8,
) -> (String, registry_breg_client::BRegProposal) {
    let seed = fixture
        .http
        .client
        .registry_contract(Some("fixture-seeder"))
        .await
        .unwrap()
        .value;
    let BRegDirectWrite::Create(create) = seed
        .select_direct_write("records.operator.create", "fixture-seeder")
        .unwrap()
    else {
        panic!("operator create")
    };
    let operator = fixture
        .http
        .client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(
                json!({"operatorCode":format!("OP-JOURNEY-{index}"),"status":"active","jurisdiction":"zone-a"}),
            ))
            .unwrap(),
            &key(&format!("journey-operator-{index}")),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value
        .data
        .record_identifier;
    let registrar = BaseRegistryClient::new(BaseRegistryClientConfig::new(breg_url.clone()))
        .unwrap()
        .with_bearer_token(
            BearerToken::new(minted(
                idp,
                json!(BREG_AUDIENCE),
                "facility-registrar",
                "registrar-client",
                "registry:facility:register",
                "human",
                Some("facility-administration"),
            ))
            .unwrap(),
        );
    let action = registrar
        .registry_contract(Some("facility-registrar"))
        .await
        .unwrap()
        .value
        .select_action("register-facility", "facility-registrar")
        .unwrap();
    let registration = BRegActionInvocationRequest::new(
        &action,
        map(json!({
        "facilityCode":format!("JOURNEY-{index}"),"name":"Civic clinic","addressLine":"1 Main Road",
        "city":"Bangkok","postalCode":"10200","operatorId":operator,"jurisdiction":"zone-a"})),
        None,
    )
    .unwrap();
    let registered = registrar
        .invoke_action(
            &action,
            &registration,
            &key(&format!("journey-register-{index}")),
        )
        .await
        .unwrap()
        .value;
    let facility = registered.results()["facility"]
        .record_identifier()
        .to_string();
    let author = BaseRegistryClient::new(BaseRegistryClientConfig::new(breg_url.clone()))
        .unwrap()
        .with_bearer_token(
            BearerToken::new(minted(
                idp,
                json!(BREG_AUDIENCE),
                "facility-author",
                "author-client",
                "registry:facility:correction:submit",
                "human",
                Some("facility-administration"),
            ))
            .unwrap(),
        );
    let action = author
        .registry_contract(Some("facility-correction-author"))
        .await
        .unwrap()
        .value
        .select_action("correct-address", "facility-correction-author")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"facilityId":facility,
        "addressLine":"3 Civic Road","city":"Chiang Mai","postalCode":"50000"})),
        None,
    )
    .unwrap();
    let draft = author
        .start_proposal(&action, &input, &key(&format!("journey-start-{index}")))
        .await
        .unwrap()
        .value;
    let submit = author
        .prepare_proposal(
            &draft,
            "submit",
            json!({}),
            &key(&format!("journey-submit-{index}")),
        )
        .unwrap();
    let submitted = author.execute_proposal(&submit).await.unwrap().value;
    (facility, submitted)
}
fn minted(
    idp: &MockIdp,
    audience: Value,
    subject: &str,
    client: &str,
    scope: &str,
    kind: &str,
    purpose: Option<&str>,
) -> String {
    let mut claims = json!({"aud":audience,"sub":subject,"azp":client,"registry_principal":subject,
        "scope":scope,"registry_actor_kind":kind,"jurisdiction":"zone-a"});
    if let Some(purpose) = purpose {
        claims["registry_purpose"] = json!(purpose);
    }
    idp.mint_token(claims)
}
async fn post_review(url: &Url, token: &str, body: &Value, key: &str) -> (StatusCode, Value) {
    let response = reqwest::Client::new()
        .post(url.join("v1/review-requests").unwrap())
        .bearer_auth(token)
        .header("registry-review-profile", "requester")
        .header("idempotency-key", key)
        .json(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json().await.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_proposal_requires_pinned_casework_approval_before_breg_apply() {
    let idp = MockIdp::start().await;
    let scratch = tempfile::tempdir().unwrap();
    let initial = compile(&canonical_source());
    let exported = export(&initial);
    let project = project(scratch.path(), &idp, &exported);
    let binding = project
        .compile_policy("facility-address-review")
        .unwrap()
        .binding();
    let mut source = canonical_source();
    let actions = source["actions"].as_array_mut().unwrap();
    let correction = actions
        .iter_mut()
        .find(|action| action["id"] == "correct-address")
        .unwrap();
    correction["execution"]["proposal"]["review"]["policy"] =
        serde_json::to_value(&binding).unwrap();
    let registry = compile(&source);
    let native = export(&registry);
    assert_eq!(
        native.contract, exported.contract,
        "the source schema does not depend on the Casework pin"
    );
    let live_approval = Arc::new(LiveApproval::default());
    let approval_for_fixture = Arc::clone(&live_approval);
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry,
        claims("fixture:seed", "facility-administration"),
        move |service| {
            service.with_proposal_review_substitute_for_test(review_binding(), approval_for_fixture)
        },
    )
    .await;
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![BREG_AUDIENCE.into()]);
    verifier.allowed_clients = vec![
        "casework-service".into(),
        "casework-human".into(),
        "other-service".into(),
        "registrar-client".into(),
        "author-client".into(),
    ];
    let authenticator = RegistryAuthenticator::new(
        &fixture.registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            registry_platform_httputil::FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".into())),
    )
    .unwrap();
    let batch_reads = Arc::new(AtomicUsize::new(0));
    let scalar_reads = Arc::new(AtomicUsize::new(0));
    let batch_counter = batch_reads.clone();
    let scalar_counter = scalar_reads.clone();
    let (breg_url, breg_server) = serve(
        authenticated_router(fixture.service(), Arc::new(authenticator)).layer(
            axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    let batch = batch_counter.clone();
                    let scalar = scalar_counter.clone();
                    async move {
                        if request.uri().path() == "/v1/proposals/review-context" {
                            batch.fetch_add(1, Ordering::SeqCst);
                        } else if request.uri().path().ends_with("/review-context") {
                            scalar.fetch_add(1, Ordering::SeqCst);
                        }
                        next.run(request).await
                    }
                },
            ),
        ),
    )
    .await;
    let (facility, proposal) = start_proposal(&fixture, &breg_url, &idp, 1).await;
    let status_token = minted(
        &idp,
        json!(BREG_AUDIENCE),
        "casework-service",
        "casework-service",
        "registry:proposal:review-status",
        "service",
        Some("facility-review"),
    );
    let breg_client = BaseRegistryClient::new(BaseRegistryClientConfig::new(breg_url.clone()))
        .unwrap()
        .with_bearer_token(BearerToken::new(status_token).unwrap());
    let provider = Arc::new(
        BregContextProvider::new(
            "facility".into(),
            native,
            breg_client,
            "casework-review-status".into(),
        )
        .unwrap(),
    );
    let (store, admin, schema) = casework_store().await;
    admin
        .execute(
            "INSERT INTO casework_teams(team_id,revision) VALUES('reviewers',1)",
            &[],
        )
        .await
        .unwrap();
    admin.execute("INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('review','reviewers',1)", &[]).await.unwrap();
    admin.execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('reviewers',$1,'reviewer-one','staff')", &[&idp.issuer()]).await.unwrap();
    admin.execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('reviewers',$1,'supervisor-one','supervisor')", &[&idp.issuer()]).await.unwrap();
    let service = CaseworkService::new(
        store.clone(),
        project.clone(),
        [provider as Arc<dyn ReviewContextProvider>],
    )
    .unwrap();
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![CASEWORK_AUDIENCE.into()]);
    verifier.allowed_clients = vec![
        "facility-registry".into(),
        "casework-human".into(),
        "other-service".into(),
    ];
    let casework_auth = CaseworkAuthenticator::new(
        &project,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            registry_platform_httputil::FetchUrlPolicy::dev(),
        )),
        HumanIdentityConfig::default(),
    );
    let (casework_url, casework_server) = serve(casework_router(HttpState {
        service,
        authenticator: Arc::new(casework_auth),
        project: Arc::new(project.clone()),
    }))
    .await;
    let proposal_id = Uuid::parse_str(proposal.id()).unwrap();
    let row = fixture.database.admin.query_one("SELECT create_request FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&proposal_id]).await.unwrap();
    let create: Value = row.get(0);
    assert_eq!(create["policy"], serde_json::to_value(&binding).unwrap());
    assert_eq!(create["subject"]["id"], proposal.id());
    assert_eq!(
        create["subject"]["digest"],
        proposal.effect_digest().unwrap()
    );
    let producer = minted(
        &idp,
        json!(CASEWORK_AUDIENCE),
        "facility-review-producer",
        "facility-registry",
        "casework:reviews:request",
        "service",
        None,
    );
    assert!(live_approval
        .casework
        .set((
            ReviewClient::new(registry_review_client::ReviewClientConfig::new(
                casework_url.clone(),
            ))
            .unwrap(),
            HttpBearerToken::new(producer.clone()).unwrap(),
        ))
        .is_ok());
    let authority = Arc::new(
        ReviewAuthorityClient::new(
            "casework".into(),
            ReviewClient::new(registry_review_client::ReviewClientConfig::new(
                casework_url.clone(),
            ))
            .unwrap(),
            Arc::new(StaticToken::new(producer.clone()).unwrap()),
            "requester".into(),
            "facility-registry".into(),
            7,
            None,
            None,
        )
        .unwrap(),
    );
    let authorities =
        ReviewAuthorityRegistry::new(BTreeMap::from([("casework".into(), authority)])).unwrap();
    assert!(
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authorities,
            &fixture.mutations,
        )
        .await
        .unwrap()
    );
    let row = fixture.database.admin.query_one("SELECT state,accepted_binding,last_error_code FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&proposal_id]).await.unwrap();
    assert_eq!(
        row.get::<_, String>(0),
        "accepted",
        "{:?}",
        row.get::<_, Option<String>>(2)
    );
    let accepted: registry_review_client::ReviewRequestAccepted =
        serde_json::from_value(row.get(1)).unwrap();
    assert_eq!(accepted.subject.id, proposal.id());
    let other = minted(
        &idp,
        json!(CASEWORK_AUDIENCE),
        "other-service",
        "other-service",
        "casework:reviews:request",
        "service",
        None,
    );
    let (status, _) = post_review(&casework_url, &other, &create, "other-producer").await;
    assert!(status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND);
    let human = minted(
        &idp,
        json!([CASEWORK_AUDIENCE, BREG_AUDIENCE]),
        "reviewer-one",
        "casework-human",
        "casework:staff registry:proposal:review",
        "human",
        Some("facility-review"),
    );
    let (_, batch_proposal) = start_proposal(&fixture, &breg_url, &idp, 99).await;
    assert!(
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authorities,
            &fixture.mutations
        )
        .await
        .unwrap()
    );
    let extra_id = Uuid::parse_str(batch_proposal.id()).unwrap();
    let extra_row = fixture.database.admin.query_one(
        "SELECT accepted_binding FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&extra_id]).await.unwrap();
    let extra_accepted: registry_review_client::ReviewRequestAccepted =
        serde_json::from_value(extra_row.get(0)).unwrap();
    batch_reads.store(0, Ordering::SeqCst);
    scalar_reads.store(0, Ordering::SeqCst);
    let page = reqwest::Client::new()
        .get(
            casework_url
                .join("v1/review-tasks?queue=review&limit=25")
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let page: Value = page.json().await.unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert_eq!(
        batch_reads.load(Ordering::SeqCst),
        1,
        "two unique BReg subjects use one bounded exchange"
    );
    assert_eq!(
        scalar_reads.load(Ordering::SeqCst),
        0,
        "the inbox sends no scalar context exchange"
    );
    let cancellation = reqwest::Client::new()
        .post(
            casework_url
                .join(&format!(
                    "v1/review-requests/{}/cancel",
                    extra_accepted.request_id
                ))
                .unwrap(),
        )
        .bearer_auth(&producer)
        .header("registry-review-profile", "requester")
        .header("idempotency-key", "batch-canary-cancel")
        .json(&json!({"subject":extra_accepted.subject,"reason":"batch proof complete"}))
        .send()
        .await
        .unwrap();
    assert!(
        cancellation.status().is_success(),
        "synthetic batch cancellation returned {}",
        cancellation.status()
    );
    let task = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|task| task["subject"]["id"] == proposal.id())
        .unwrap();
    let id = task["taskId"].as_str().unwrap();
    let response = reqwest::Client::new()
        .get(casework_url.join(&format!("v1/review-tasks/{id}")).unwrap())
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    let status = response.status();
    let shown: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{shown}");
    assert_eq!(shown["subject"]["id"], proposal.id(), "{shown}");
    let context = reqwest::Client::new()
        .get(
            casework_url
                .join(&format!("v1/review-tasks/{id}/context"))
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    assert_eq!(context.status(), StatusCode::OK);
    let context: Value = context.json().await.unwrap();
    assert_eq!(context["subject"]["id"], proposal.id(), "{context}");
    assert_eq!(
        context["context"]["projection"]["display"]["facilityId"], facility,
        "{context}"
    );
    assert!(
        !fixture
            .mutations
            .run_automatic_proposal_once_for_test()
            .await
            .unwrap(),
        "a submitted review cannot grant BReg application authority"
    );
    let claimed = reqwest::Client::new()
        .post(
            casework_url
                .join(&format!("v1/review-tasks/{id}/claim"))
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .header(
            "if-match",
            format!("\"{}\"", shown["revision"].as_i64().unwrap()),
        )
        .header("idempotency-key", "native-claim")
        .send()
        .await
        .unwrap();
    let claim_status = claimed.status();
    let claimed: Value = claimed.json().await.unwrap();
    assert_eq!(claim_status, StatusCode::OK, "{claimed}");
    let decided = reqwest::Client::new()
        .post(
            casework_url
                .join(&format!("v1/review-tasks/{id}/decisions"))
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .header(
            "if-match",
            format!("\"{}\"", claimed["revision"].as_i64().unwrap()),
        )
        .header("idempotency-key", "native-approve")
        .json(&json!({"decision":{"type":"approve","outcome":"approved"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(decided.status(), StatusCode::NO_CONTENT);
    let supervisor = minted(
        &idp,
        json!([CASEWORK_AUDIENCE, BREG_AUDIENCE]),
        "supervisor-one",
        "casework-human",
        "casework:supervisor registry:proposal:review",
        "human",
        Some("facility-review"),
    );
    let supervisor_page = reqwest::Client::new()
        .get(
            casework_url
                .join("v1/review-tasks?queue=review&limit=25")
                .unwrap(),
        )
        .bearer_auth(&supervisor)
        .header("registry-casework-profile", "supervisor")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    assert_eq!(supervisor_page.status(), StatusCode::OK);
    let supervisor_page: Value = supervisor_page.json().await.unwrap();
    let supervisor_task = supervisor_page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|task| task["requestId"] == accepted.request_id.to_string())
        .expect("the second-stage native Proposal task is reviewable");
    let supervisor_task_id = supervisor_task["taskId"].as_str().unwrap().to_owned();
    let supervisor_claim = reqwest::Client::new()
        .post(
            casework_url
                .join(&format!("v1/review-tasks/{supervisor_task_id}/claim"))
                .unwrap(),
        )
        .bearer_auth(&supervisor)
        .header("registry-casework-profile", "supervisor")
        .header("registry-source-profile", "proposal-reviewer")
        .header(
            "if-match",
            format!("\"{}\"", supervisor_task["revision"].as_i64().unwrap()),
        )
        .header("idempotency-key", "native-supervisor-claim")
        .send()
        .await
        .unwrap();
    let supervisor_claim_status = supervisor_claim.status();
    let supervisor_claim: Value = supervisor_claim.json().await.unwrap();
    assert_eq!(
        supervisor_claim_status,
        StatusCode::OK,
        "{supervisor_claim}"
    );
    let supervisor_decision = reqwest::Client::new()
        .post(
            casework_url
                .join(&format!("v1/review-tasks/{supervisor_task_id}/decisions"))
                .unwrap(),
        )
        .bearer_auth(&supervisor)
        .header("registry-casework-profile", "supervisor")
        .header("registry-source-profile", "proposal-reviewer")
        .header(
            "if-match",
            format!("\"{}\"", supervisor_claim["revision"].as_i64().unwrap()),
        )
        .header("idempotency-key", "native-supervisor-approve")
        .json(&json!({"decision":{"type":"approve","outcome":"approved"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(supervisor_decision.status(), StatusCode::NO_CONTENT);
    let (review_client, review_token) = live_approval.casework.get().unwrap();
    let ReviewResultResponse::Available(result) = review_client
        .result(ReviewAuth::new(review_token, "requester"), &accepted)
        .await
        .unwrap()
    else {
        panic!("the producer must read its actual terminal Casework result");
    };
    assert_eq!(result.value.status, ReviewResultStatus::Approved);
    for _ in 0..8 {
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authorities,
            &fixture.mutations,
        )
        .await
        .unwrap();
        let row = fixture.database.admin.query_one("SELECT count(*) FROM registry_internal.registry_proposal_review_results WHERE proposal_id=$1", &[&proposal_id]).await.unwrap();
        if row.get::<_, i64>(0) == 1 {
            break;
        }
    }
    let applied_work = fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap();
    let state = fixture.database.admin.query_one("SELECT state,result_poll_attempts,next_result_poll_at<=transaction_timestamp() FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&proposal_id]).await.unwrap();
    let results = fixture.database.admin.query_one("SELECT count(*) FROM registry_internal.registry_proposal_review_results WHERE proposal_id=$1", &[&proposal_id]).await.unwrap();
    assert!(
        applied_work,
        "review state={}, poll_attempts={}, poll_due={}, result_rows={}",
        state.get::<_, String>(0),
        state.get::<_, i32>(1),
        state.get::<_, bool>(2),
        results.get::<_, i64>(0)
    );
    let author = BaseRegistryClient::new(BaseRegistryClientConfig::new(breg_url.clone()))
        .unwrap()
        .with_bearer_token(
            BearerToken::new(minted(
                &idp,
                json!(BREG_AUDIENCE),
                "facility-author",
                "author-client",
                "registry:facility:correction:submit",
                "human",
                Some("facility-administration"),
            ))
            .unwrap(),
        );
    let applied = author.read_proposal(&proposal).await.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    let decided_task = reqwest::Client::new()
        .get(casework_url.join(&format!("v1/review-tasks/{id}")).unwrap())
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    let decided_task_status = decided_task.status();
    let decided_task: Value = decided_task.json().await.unwrap();
    assert_eq!(decided_task_status, StatusCode::OK, "{decided_task}");
    assert_eq!(decided_task["taskId"], id, "{decided_task}");
    assert_eq!(decided_task["state"], "decided", "{decided_task}");
    let retained = admin
        .query_one(
            "SELECT result_erased_at IS NULL,result_available_until>now() \
             FROM casework_review_requests WHERE request_id=$1",
            &[&accepted.request_id],
        )
        .await
        .unwrap();
    assert!(retained.get::<_, bool>(0));
    assert!(retained.get::<_, bool>(1));
    let casework_only_human = minted(
        &idp,
        json!(CASEWORK_AUDIENCE),
        "reviewer-one",
        "casework-human",
        "casework:staff",
        "human",
        None,
    );
    let retained_task = reqwest::Client::new()
        .get(casework_url.join(&format!("v1/review-tasks/{id}")).unwrap())
        .bearer_auth(&casework_only_human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    let retained_task_status = retained_task.status();
    let retained_task: Value = retained_task.json().await.unwrap();
    assert_eq!(retained_task_status, StatusCode::OK, "{retained_task}");
    assert_eq!(retained_task["taskId"], id, "{retained_task}");
    assert_eq!(retained_task["state"], "decided", "{retained_task}");
    let concealed_context = reqwest::Client::new()
        .get(
            casework_url
                .join(&format!("v1/review-tasks/{id}/context"))
                .unwrap(),
        )
        .bearer_auth(&casework_only_human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    assert_eq!(concealed_context.status(), StatusCode::NOT_FOUND);
    let retained_note = reqwest::Client::new()
        .post(
            casework_url
                .join(&format!("v1/review-requests/{}/notes", accepted.request_id))
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .header("idempotency-key", "native-retained-note")
        .json(&json!({"audience":"reviewers","note":"decision archived"}))
        .send()
        .await
        .unwrap();
    let retained_note_status = retained_note.status();
    let retained_note: Value = retained_note.json().await.unwrap();
    assert!(retained_note_status.is_success(), "{retained_note}");
    let retained_history = reqwest::Client::new()
        .get(
            casework_url
                .join(&format!(
                    "v1/review-requests/{}/history",
                    accepted.request_id
                ))
                .unwrap(),
        )
        .bearer_auth(&casework_only_human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    let retained_history_status = retained_history.status();
    let retained_history: Value = retained_history.json().await.unwrap();
    assert_eq!(
        retained_history_status,
        StatusCode::OK,
        "{retained_history}"
    );
    assert!(
        retained_history["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["eventId"] == retained_note["eventId"]),
        "{retained_history}"
    );
    let former_reviewer = minted(
        &idp,
        json!(CASEWORK_AUDIENCE),
        "former-reviewer",
        "casework-human",
        "casework:staff",
        "human",
        None,
    );
    let unauthorized_terminal_task = reqwest::Client::new()
        .get(casework_url.join(&format!("v1/review-tasks/{id}")).unwrap())
        .bearer_auth(&former_reviewer)
        .header("registry-casework-profile", "staff")
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized_terminal_task.status(), StatusCode::NOT_FOUND);
    // A decided task stays listed while BReg still shows the applied
    // Proposal to the reader, although it is no longer reviewable there.
    let decided_list = |path: &'static str, token: String, profile: &'static str| {
        let url = casework_url.join(path).unwrap();
        async move {
            let response = reqwest::Client::new()
                .get(url)
                .bearer_auth(&token)
                .header("registry-casework-profile", profile)
                .header("registry-source-profile", "proposal-reviewer")
                .send()
                .await
                .unwrap();
            let status = response.status();
            let page: Value = response.json().await.unwrap();
            assert_eq!(status, StatusCode::OK, "{page}");
            page
        }
    };
    let own = decided_list(
        "v1/review-tasks/own-decisions?queue=review",
        human.clone(),
        "staff",
    )
    .await;
    assert!(
        own["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["taskId"] == id),
        "the reviewer's own decision stays listed after BReg applied: {own}"
    );
    let supervised = decided_list(
        "v1/review-tasks/supervision?queue=review",
        supervisor.clone(),
        "supervisor",
    )
    .await;
    assert!(
        supervised["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["taskId"] == id),
        "the supervisor still sees the decided task after BReg applied: {supervised}"
    );
    // Backdate the whole 30-day retention window so expiry remains after
    // completion even when the preceding HTTP checks take less than a second.
    admin
        .execute(
            "UPDATE casework_review_requests SET terminal_at=now()-interval '31 days', \
             result_available_until=now()-interval '1 day' WHERE request_id=$1",
            &[&accepted.request_id],
        )
        .await
        .unwrap();
    let expired_task = reqwest::Client::new()
        .get(casework_url.join(&format!("v1/review-tasks/{id}")).unwrap())
        .bearer_auth(&casework_only_human)
        .header("registry-casework-profile", "staff")
        .send()
        .await
        .unwrap();
    assert_eq!(expired_task.status(), StatusCode::NOT_FOUND);
    let (_, pending_proposal) = start_proposal(&fixture, &breg_url, &idp, 2).await;
    let pending_id = Uuid::parse_str(pending_proposal.id()).unwrap();
    let row = fixture.database.admin.query_one("SELECT create_request FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&pending_id]).await.unwrap();
    let pending_create: Value = row.get(0);
    assert_eq!(
        pending_create["policy"],
        serde_json::to_value(&binding).unwrap()
    );
    for _ in 0..12 {
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authorities,
            &fixture.mutations,
        )
        .await
        .unwrap();
        let row = fixture.database.admin.query_one("SELECT state FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&pending_id]).await.unwrap();
        if row.get::<_, String>(0) == "accepted" {
            break;
        }
    }
    let row = fixture.database.admin.query_one("SELECT state,accepted_binding,last_error_code FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&pending_id]).await.unwrap();
    assert_eq!(
        row.get::<_, String>(0),
        "accepted",
        "{:?}",
        row.get::<_, Option<String>>(2)
    );
    let pending_accepted: registry_review_client::ReviewRequestAccepted =
        serde_json::from_value(row.get(1)).unwrap();
    let page = reqwest::Client::new()
        .get(
            casework_url
                .join("v1/review-tasks?queue=review&limit=25")
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let page: Value = page.json().await.unwrap();
    let pending_task = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|task| task["requestId"] == pending_accepted.request_id.to_string())
        .expect("the pending native Proposal is reviewable before supersession");
    let pending_task_id = pending_task["taskId"].as_str().unwrap().to_owned();
    let pending_revision = pending_task["revision"].as_i64().unwrap();
    let mut changed = pending_create.clone();
    changed["subject"]["version"] = json!("999");
    changed["requesterReference"] = json!("forged-version");
    let (status, moved) =
        post_review(&casework_url, &producer, &changed, "moved-binding-pending").await;
    assert_eq!(status, StatusCode::CREATED, "{moved}");
    let ReviewResultResponse::Available(superseded) = review_client
        .result(
            ReviewAuth::new(review_token, "requester"),
            &pending_accepted,
        )
        .await
        .unwrap()
    else {
        panic!("the original pending review must have a terminal result after supersession");
    };
    assert_eq!(superseded.value.status, ReviewResultStatus::Superseded);
    let original = admin
        .query_one(
            "SELECT lifecycle FROM casework_review_requests WHERE request_id=$1",
            &[&pending_accepted.request_id],
        )
        .await
        .unwrap();
    assert_eq!(original.get::<_, String>(0), "superseded");
    let closed = admin
        .query_one(
            "SELECT state FROM casework_review_tasks WHERE task_id=$1",
            &[&Uuid::parse_str(&pending_task_id).unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(closed.get::<_, String>(0), "closed");
    let claim = reqwest::Client::new()
        .post(
            casework_url
                .join(&format!("v1/review-tasks/{pending_task_id}/claim"))
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .header("if-match", format!("\"{pending_revision}\""))
        .header("idempotency-key", "superseded-claim")
        .send()
        .await
        .unwrap();
    assert_eq!(claim.status(), StatusCode::NOT_FOUND);
    let replacement_id = Uuid::parse_str(moved["requestId"].as_str().unwrap()).unwrap();
    let replacement = admin
        .query_one(
            "SELECT lifecycle,subject_version FROM casework_review_requests WHERE request_id=$1",
            &[&replacement_id],
        )
        .await
        .unwrap();
    assert_eq!(replacement.get::<_, String>(0), "reviewing");
    assert_eq!(replacement.get::<_, String>(1), "999");
    let source_still_pending = author.read_proposal(&pending_proposal).await.unwrap().value;
    assert_eq!(source_still_pending.state(), BRegProposalState::Submitted);
    assert_eq!(
        source_still_pending.submission_version(),
        pending_proposal.submission_version()
    );
    assert_eq!(
        source_still_pending.effect_digest(),
        pending_proposal.effect_digest()
    );
    let page = reqwest::Client::new()
        .get(
            casework_url
                .join("v1/review-tasks?queue=review&limit=25")
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let page: Value = page.json().await.unwrap();
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(
                |task| task["requestId"] != pending_accepted.request_id.to_string()
                    && task["requestId"] != replacement_id.to_string()
            ),
        "neither the superseded task nor forged binding is visible: {page}"
    );
    let (_, rejected_proposal) = start_proposal(&fixture, &breg_url, &idp, 3).await;
    let rejected_id = Uuid::parse_str(rejected_proposal.id()).unwrap();
    for _ in 0..12 {
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authorities,
            &fixture.mutations,
        )
        .await
        .unwrap();
        let row = fixture.database.admin.query_one("SELECT state FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&rejected_id]).await.unwrap();
        if row.get::<_, String>(0) == "accepted" {
            break;
        }
    }
    let row = fixture.database.admin.query_one("SELECT state,accepted_binding FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&rejected_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "accepted");
    let rejected_accepted: registry_review_client::ReviewRequestAccepted =
        serde_json::from_value(row.get(1)).unwrap();
    let page = reqwest::Client::new()
        .get(
            casework_url
                .join("v1/review-tasks?queue=review&limit=25")
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let page: Value = page.json().await.unwrap();
    let rejected_task = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|task| task["requestId"] == rejected_accepted.request_id.to_string())
        .expect("the third native Proposal is reviewable");
    let rejected_task_id = rejected_task["taskId"].as_str().unwrap().to_owned();
    let claimed = reqwest::Client::new()
        .post(
            casework_url
                .join(&format!("v1/review-tasks/{rejected_task_id}/claim"))
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .header(
            "if-match",
            format!("\"{}\"", rejected_task["revision"].as_i64().unwrap()),
        )
        .header("idempotency-key", "native-reject-claim")
        .send()
        .await
        .unwrap();
    let claim_status = claimed.status();
    let claimed: Value = claimed.json().await.unwrap();
    assert_eq!(claim_status, StatusCode::OK, "{claimed}");
    let decided = reqwest::Client::new()
        .post(
            casework_url
                .join(&format!("v1/review-tasks/{rejected_task_id}/decisions"))
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .header(
            "if-match",
            format!("\"{}\"", claimed["revision"].as_i64().unwrap()),
        )
        .header("idempotency-key", "native-reject")
        .json(&json!({"decision":{"type":"reject","outcome":"rejected",
            "reason":"the address does not match the survey","publicReason":"address not confirmed"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(decided.status(), StatusCode::NO_CONTENT);
    for _ in 0..8 {
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authorities,
            &fixture.mutations,
        )
        .await
        .unwrap();
        if author
            .read_proposal(&rejected_proposal)
            .await
            .unwrap()
            .value
            .state()
            == BRegProposalState::Rejected
        {
            break;
        }
    }
    assert_eq!(
        author
            .read_proposal(&rejected_proposal)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Rejected
    );
    // The rejected Proposal is no longer reviewable at BReg; the reviewer
    // still annotates the settled request and reads its history.
    let note = reqwest::Client::new()
        .post(
            casework_url
                .join(&format!(
                    "v1/review-requests/{}/notes",
                    rejected_accepted.request_id
                ))
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .header("idempotency-key", "native-reject-note")
        .json(&json!({"audience":"reviewers","note":"survey copy filed"}))
        .send()
        .await
        .unwrap();
    let note_status = note.status();
    let note_body = note.text().await.unwrap();
    assert!(note_status.is_success(), "{note_status} {note_body}");
    let history = reqwest::Client::new()
        .get(
            casework_url
                .join(&format!(
                    "v1/review-requests/{}/history",
                    rejected_accepted.request_id
                ))
                .unwrap(),
        )
        .bearer_auth(&human)
        .header("registry-casework-profile", "staff")
        .header("registry-source-profile", "proposal-reviewer")
        .send()
        .await
        .unwrap();
    let history_status = history.status();
    let history: Value = history.json().await.unwrap();
    assert_eq!(history_status, StatusCode::OK, "{history}");
    assert!(
        !history["items"].as_array().unwrap().is_empty(),
        "{history}"
    );
    casework_server.abort();
    breg_server.abort();
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    fixture.finish().await;
}
