// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "../../registry-breg/tests/support/postgres_harness.rs"]
mod breg_postgres_harness;

use std::collections::BTreeMap;
use std::env;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use breg_postgres_harness::TestDatabase;
use registry_breg::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::mutation::MutationFaultPoint;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_breg::review_store::{reconcile_result, run_review_authority_once_for_test};
use registry_breg::runtime_config::parse_runtime_config;
use registry_casework::{
    router as casework_router, CaseworkAuthenticator, CaseworkService, DatabaseConfig, HttpState,
    HumanIdentityConfig, PostgresStore, ReviewResultRead, ReviewTaskDecisionRequest,
};
use registry_casework_core::{
    AccessProfile, ActiveSubjectsPage, ActorContext, AuthoritativeObservation, CallerSubjectView,
    CaseworkIdentity, CaseworkProject, CaseworkRole, DiscoveryCursor, EphemeralCredential,
    EventRequest, ExecutePreparedRequest, InboxPolicy, IssuerPrincipal, OccurrenceKind,
    OccurrenceState, PrepareActionRequest, PreparedSourceAttempt, QueuePolicy,
    ReviewContextStrategy, ReviewCreateRequest, ReviewKindPolicy, ReviewKindPurpose,
    ReviewProducerPolicy, ReviewRequestAccepted, ReviewRetentionPolicy, ReviewStagePolicy,
    ReviewerDecisionKind, SourceAdapter, SourceAdapterError, SourceBinding, SourceReceipt,
    SubjectRef, TransitionHint,
};
use registry_platform_audit::AuditProfile;
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use reqwest::{Method, StatusCode, Url};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_postgres::NoTls;
use uuid::Uuid;
use zeroize::Zeroizing;

const BREG_AUDIENCE: &str = "urn:test:breg-review-source";
const CASEWORK_AUDIENCE: &str = BREG_AUDIENCE;
const REGISTRY_ID: &str = "composed-review-registry";
const PACKAGE_REVISION: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Clone)]
struct BregReviewSource {
    endpoint: Arc<Mutex<Option<Url>>>,
    reader_token: String,
}

#[async_trait]
impl SourceAdapter for BregReviewSource {
    fn source_id(&self) -> &str {
        REGISTRY_ID
    }

    fn binding_generation(&self) -> &str {
        "composed-breg-source-v1"
    }

    async fn verify_transition(
        &self,
        _request: EventRequest,
    ) -> Result<TransitionHint, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }

    async fn read_authoritative(
        &self,
        subject: &SubjectRef,
    ) -> Result<AuthoritativeObservation, SourceAdapterError> {
        // The subject kind is the registry's own request entity, the same
        // identifier the production adapter validates against its config.
        if subject.source_id != REGISTRY_ID || subject.kind != "correction-request" {
            return Err(SourceAdapterError::Invalid);
        }
        let endpoint = self
            .endpoint
            .lock()
            .map_err(|_| SourceAdapterError::Unavailable)?
            .clone()
            .ok_or(SourceAdapterError::Unavailable)?;
        let url = endpoint
            .join(&format!(
                "/v1/records/correction-requests/{}?accessProfile=casework-reviewer",
                subject.id
            ))
            .map_err(|_| SourceAdapterError::Invalid)?;
        let response = reqwest::Client::new()
            .get(url)
            .bearer_auth(&self.reader_token)
            .send()
            .await
            .map_err(|_| SourceAdapterError::Unavailable)?;
        if response.status() == StatusCode::FORBIDDEN || response.status() == StatusCode::NOT_FOUND
        {
            return Err(SourceAdapterError::Concealed);
        }
        if response.status() != StatusCode::OK {
            return Err(SourceAdapterError::Unavailable);
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| SourceAdapterError::Unavailable)?;
        let data = &body["data"];
        let request = &data["request"];
        if !data.is_object() || !request.is_object() {
            return Err(SourceAdapterError::Invalid);
        }
        let version = request["proposalVersion"]
            .as_u64()
            .ok_or(SourceAdapterError::Invalid)?
            .to_string();
        let integrity = request["effectDigest"]
            .as_str()
            .ok_or(SourceAdapterError::Invalid)?
            .to_owned();
        let source_revision = data["revisionIdentifier"]
            .as_str()
            .ok_or(SourceAdapterError::Invalid)?
            .to_owned();
        // The occurrence-state mapping mirrors the production BReg adapter:
        // submitted requests stay active unless their review projection shows
        // an application in flight or settled, and every other lifecycle state
        // is terminal for review work.
        let state = if request["bregState"].as_str() == Some("submitted") {
            match request
                .get("review")
                .and_then(|review| review.pointer("/application/state"))
                .and_then(Value::as_str)
            {
                Some("queued") | Some("applying") => OccurrenceState::Synchronizing,
                Some("applied") => OccurrenceState::Completed,
                Some("ready") => OccurrenceState::Open,
                _ if request["actions"].as_array().is_some_and(|actions| {
                    actions
                        .iter()
                        .any(|action| action["operation"].as_str() == Some("apply_request"))
                }) =>
                {
                    OccurrenceState::Open
                }
                _ => OccurrenceState::WaitingApplication,
            }
        } else {
            match request["bregState"].as_str() {
                Some("applied") => OccurrenceState::Completed,
                Some("cancelled") => OccurrenceState::Cancelled,
                _ => OccurrenceState::Superseded,
            }
        };
        Ok(AuthoritativeObservation {
            subject: subject.clone(),
            occurrence_key: format!("application:{version}"),
            ordered_revision: source_revision
                .parse()
                .map_err(|_| SourceAdapterError::Invalid)?,
            // This double pins the representation to the revision; the
            // preflight consumes only the occurrence state, and no journey
            // path compares representation etags.
            representation_etag: format!("\"{source_revision}\""),
            binding: SourceBinding {
                source_revision,
                version,
                integrity: Some(integrity),
                generation: self.binding_generation().to_owned(),
            },
            display_reference: None,
            occurrence_kind: OccurrenceKind::Application,
            stage: None,
            submitted_at: None,
            stage_entered_at: None,
            review_timing: None,
            routing_context: None,
            state,
            remaining_actions: Vec::new(),
        })
    }

    async fn discover_active(
        &self,
        _cursor: Option<&DiscoveryCursor>,
        _limit: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
        Ok(ActiveSubjectsPage {
            subjects: Vec::new(),
            next_cursor: None,
        })
    }

    async fn read_for_caller(
        &self,
        subject: &SubjectRef,
        source_profile_id: &str,
        credential: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        if subject.source_id != REGISTRY_ID
            || subject.kind != "correction-request"
            || source_profile_id != "casework-reviewer"
        {
            return Err(SourceAdapterError::Invalid);
        }
        let endpoint = self
            .endpoint
            .lock()
            .map_err(|_| SourceAdapterError::Unavailable)?
            .clone()
            .ok_or(SourceAdapterError::Unavailable)?;
        let url = endpoint
            .join(&format!(
                "/v1/records/correction-requests/{}?accessProfile=casework-reviewer",
                subject.id
            ))
            .map_err(|_| SourceAdapterError::Invalid)?;
        let response = reqwest::Client::new()
            .get(url)
            .bearer_auth(credential.expose())
            .send()
            .await
            .map_err(|_| SourceAdapterError::Unavailable)?;
        if response.status() == StatusCode::FORBIDDEN || response.status() == StatusCode::NOT_FOUND
        {
            return Err(SourceAdapterError::Concealed);
        }
        if response.status() != StatusCode::OK {
            return Err(SourceAdapterError::Unavailable);
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| SourceAdapterError::Unavailable)?;
        let request = body["data"]["request"]
            .as_object()
            .ok_or(SourceAdapterError::Invalid)?;
        let version = request["proposalVersion"]
            .as_u64()
            .ok_or(SourceAdapterError::Invalid)?
            .to_string();
        let integrity = request["effectDigest"]
            .as_str()
            .ok_or(SourceAdapterError::Invalid)?
            .to_owned();
        Ok(CallerSubjectView {
            subject: subject.clone(),
            binding: SourceBinding {
                source_revision: body["data"]["revisionIdentifier"]
                    .as_str()
                    .ok_or(SourceAdapterError::Invalid)?
                    .to_owned(),
                version,
                integrity: Some(integrity),
                generation: self.binding_generation().to_owned(),
            },
            display_reference: None,
            disclosed: BTreeMap::new(),
            permitted_operations: Vec::new(),
        })
    }

    async fn prepare_action(
        &self,
        _request: PrepareActionRequest<'_>,
    ) -> Result<PreparedSourceAttempt, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }

    async fn execute_prepared(
        &self,
        _request: ExecutePreparedRequest<'_>,
    ) -> Result<SourceReceipt, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
}

fn profile(id: &str, role: CaseworkRole) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        principal_claim: "registry_principal".to_owned(),
        required_scopes: vec![format!("casework:{id}")],
        role,
    }
}

fn casework_project(issuer: &str) -> CaseworkProject {
    CaseworkProject {
        api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
        kind: registry_casework_core::CASEWORK_KIND.to_owned(),
        casework: CaseworkIdentity {
            id: "composed-review-authority".to_owned(),
            version: "1".to_owned(),
        },
        access_profiles: vec![
            profile("first-reviewer", CaseworkRole::Staff),
            profile("second-reviewer", CaseworkRole::Staff),
            profile("supervisor", CaseworkRole::Supervisor),
            profile("administrator", CaseworkRole::Administrator),
            profile("producer", CaseworkRole::Requester),
        ],
        queues: vec![
            QueuePolicy {
                id: "first-review".to_owned(),
                label: "First review".to_owned(),
            },
            QueuePolicy {
                id: "second-review".to_owned(),
                label: "Second review".to_owned(),
            },
        ],
        sources: Vec::new(),
        review_kinds: vec![ReviewKindPolicy {
            id: "registry-correction".to_owned(),
            version: "1".to_owned(),
            purpose: ReviewKindPurpose::Approval,
            context_strategy: ReviewContextStrategy::Source,
            stages: vec![
                ReviewStagePolicy {
                    id: "first".to_owned(),
                    queue: "first-review".to_owned(),
                    deciding_profiles: vec!["first-reviewer".to_owned()],
                    required_approvals: 1,
                    exclude_initiator: false,
                    exclude_previous_stage_reviewers: false,
                },
                ReviewStagePolicy {
                    id: "second".to_owned(),
                    queue: "second-review".to_owned(),
                    deciding_profiles: vec!["second-reviewer".to_owned()],
                    required_approvals: 1,
                    exclude_initiator: false,
                    exclude_previous_stage_reviewers: true,
                },
            ],
            clocks: Vec::new(),
            retention: ReviewRetentionPolicy {
                terminal_days: 30,
                accountability_days: 90,
            },
            display_schema: json!({
                "type":"object",
                "additionalProperties":false,
                "properties":{}
            }),
            result_schema: None,
            outcomes: Vec::new(),
        }],
        review_producers: vec![ReviewProducerPolicy {
            id: "registry-producer".to_owned(),
            profile: "producer".to_owned(),
            issuer: issuer.to_owned(),
            subject: "registry-service".to_owned(),
            trusted_initiator_issuer: None,
            initiator_profile: None,
            source_namespaces: vec![REGISTRY_ID.to_owned()],
            kinds: vec!["registry-correction".to_owned()],
            recovery_days: 7,
            completion: None,
        }],
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
        task_templates: Vec::new(),
    }
}

async fn casework_fixture(
    idp: &MockIdp,
    source: BregReviewSource,
    project: CaseworkProject,
) -> (Router, CaseworkService, tokio_postgres::Client, String) {
    let directory = format!(
        "INSERT INTO casework_teams(team_id,revision) VALUES('first-team',1),('second-team',1);
         INSERT INTO casework_queue_service(queue_id,team_id,revision)
         VALUES('first-review','first-team',1),('second-review','second-team',1);
         INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind)
         VALUES('first-team','{issuer}','reviewer-one','staff'),
               ('second-team','{issuer}','reviewer-two','staff');",
        issuer = idp.issuer()
    );
    casework_fixture_with_source(idp, Arc::new(source), project, &directory).await
}

/// A Casework service with one source adapter, backed by an isolated schema
/// whose team, queue, and membership rows `directory` inserts.
async fn casework_fixture_with_source(
    idp: &MockIdp,
    source: Arc<dyn SourceAdapter>,
    project: CaseworkProject,
    directory: &str,
) -> (Router, CaseworkService, tokio_postgres::Client, String) {
    let base = env::var("BREG_TEST_DATABASE_URL").expect("BREG_TEST_DATABASE_URL");
    let schema = format!("casework_breg_journey_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let (admin, admin_connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("casework admin connection");
    tokio::spawn(async move { admin_connection.await.expect("casework admin task") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("isolated Casework schema");
    let secret_name = format!("CASEWORK_BREG_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    env::set_var(&secret_name, &scoped_url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("Casework secrets");
    let database_config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret_name}"),
        migration_url_ref: format!("secret:env/{secret_name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    PostgresStore::connect_migration(&database_config, &secrets)
        .expect("Casework migration store")
        .with_audit(registry_casework::CaseworkAudit::capture().0)
        .migrate()
        .await
        .expect("Casework migrations");
    let database = tokio_postgres::connect(&scoped_url, NoTls)
        .await
        .expect("Casework inspection connection");
    let casework_database = database.0;
    tokio::spawn(async move { database.1.await.expect("Casework inspection task") });
    casework_database
        .batch_execute(directory)
        .await
        .expect("Casework directory");
    project.check().expect("Casework project");
    let service = CaseworkService::new(
        PostgresStore::connect_runtime(&database_config, &secrets)
            .expect("Casework runtime store")
            .with_audit(registry_casework::CaseworkAudit::capture().0),
        project.clone(),
        [source],
    )
    .expect("Casework service");
    let authenticator = CaseworkAuthenticator::new(
        &project,
        oidc_verifier_config(idp.issuer(), vec![CASEWORK_AUDIENCE.to_owned()]),
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        HumanIdentityConfig::default(),
    );
    (
        casework_router(HttpState {
            service: service.clone(),
            authenticator: Arc::new(authenticator),
            project: Arc::new(project),
        }),
        service,
        casework_database,
        schema,
    )
}

fn breg_project() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"composed-review-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
          "entities":[
            {"id":"asset","primaryDataset":"main","route":"assets","mutationMode":"mutable","classification":"internal","changeControl":{"requiredFor":["patch"]},"fields":[
              {"id":"owner","type":"string","required":true,"maxLength":64,"classification":"internal"},
              {"id":"label","type":"string","required":true,"maxLength":64,"classification":"internal"}
            ]},
            {"id":"correction-request","primaryDataset":"main","route":"correction-requests","mutationMode":"mutable","classification":"internal","fields":[
              {"id":"owner","type":"string","required":true,"maxLength":64,"classification":"internal"},
              {"id":"asset","type":"reference","target":"asset","required":true,"classification":"internal"},
              {"id":"label","type":"string","required":true,"maxLength":64,"classification":"internal"}
            ],"changeRequest":{
              "effects":[{"target":{"fromField":"asset"},"operation":"patch","set":{"label":{"fromField":"label"}}}],
              "review":{"authority":"casework-a","policyId":"registry-correction"},
              "onApproved":{"mode":"manual"},
              "application":{"preconditions":{"targets":[{"id":"asset-guard","entity":"asset","fromField":"asset","requires":[{"field":"owner","equalsFromRequestField":"owner"}]}]}}
            }}
          ],
          "accessProfiles":[
            {"id":"steward","principalClaim":"registry_principal","requiredScopes":["breg:steward"],"permissions":[{"entity":"asset","operations":["create","get"],"readableFields":["owner","label"],"writableFields":["owner","label"],"rowBoundaries":[]}]},
            {"id":"submitter","principalClaim":"registry_principal","requiredScopes":["breg:submit"],"permissions":[{"entity":"correction-request","operations":["create","get","submit_request","cancel_request","revise_request"],"readableFields":["owner","asset","label"],"writableFields":["owner","asset","label"],"rowBoundaries":[]}]},
            {"id":"casework-reviewer","principalClaim":"registry_principal","requiredScopes":["breg:review-read"],"permissions":[{"entity":"correction-request","operations":["get"],"readableFields":["owner","asset","label"],"rowBoundaries":[]}]},
            {"id":"manual-applier","principalClaim":"registry_principal","requiredScopes":["breg:apply"],"permissions":[{"entity":"correction-request","operations":["get","apply_request"],"readableFields":["owner","asset","label"],"applyTargets":[{"entity":"asset","rowBoundaries":[]}],"rowBoundaries":[]}]}
          ]
        }"#,
    )
    .expect("BReg project parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("BReg project compiles")
}

struct Ready;
impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn breg_service(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    authorities: Arc<registry_breg::review_store::ReviewAuthorityRegistry>,
    fault: Option<MutationFaultPoint>,
) -> Arc<HttpService> {
    let pool = database.runtime_config.build_pool().expect("BReg pool");
    let lock = RegistryLockKey::derive(REGISTRY_ID).expect("BReg lock");
    let audit = AuditProfile::production_from_secret_bytes(vec![0x51; 32].into())
        .expect("BReg audit profile");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x52; 32]), Duration::from_secs(300))
            .expect("BReg cursors"),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock,
        Duration::from_secs(2),
        audit,
    )
    .with_review_result_source(authorities);
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
    Arc::new(
        HttpService::new(
            registry,
            ReadRuntimeIdentity {
                package_revision: identity.package_revision,
                schema_fingerprint: identity.schema_fingerprint,
            },
            reads,
            Arc::new(Ready),
            cursors,
        )
        .with_postgres_mutations(Arc::new(mutations)),
    )
}

fn breg_router(
    service: Arc<HttpService>,
    registry: &registry_breg::CompiledRegistry,
    idp: &MockIdp,
) -> Router {
    breg_router_with(
        service,
        registry,
        idp,
        oidc_verifier_config(idp.issuer(), vec![BREG_AUDIENCE.to_owned()]),
        AuthorityClaimConfig::new("registry_principal", None),
    )
}

fn breg_router_with(
    service: Arc<HttpService>,
    registry: &registry_breg::CompiledRegistry,
    idp: &MockIdp,
    verifier: registry_platform_oidc::TokenVerifierConfig,
    claims: AuthorityClaimConfig,
) -> Router {
    let authenticator = RegistryAuthenticator::new(
        registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        claims,
    )
    .expect("BReg authenticator");
    authenticated_router(service, Arc::new(authenticator))
}

async fn serve(app: Router) -> (Url, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    serve_on(listener, app)
}

/// Serve on a listener bound earlier, for services whose URLs must be known
/// before the services they call are built.
fn serve_on(listener: TcpListener, app: Router) -> (Url, tokio::task::JoinHandle<()>) {
    let address = listener.local_addr().expect("listener address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("HTTP service");
    });
    (Url::parse(&format!("http://{address}/")).unwrap(), task)
}

fn token(idp: &MockIdp, audience: &str, principal: &str, scope: &str) -> String {
    idp.mint_token(json!({
        "aud": audience,
        "registry_principal": principal,
        "scope": scope,
        "registry_actor_kind": "service"
    }))
}

/// A person's token as a stock identity provider issues it: `sub` is the
/// provider's own user identifier, and the deployment's principal travels in
/// `registry_principal`, the claim every profile in this journey reads.
fn human_token(idp: &MockIdp, principal: &str, scope: &str) -> String {
    idp.mint_token(json!({
        "aud": BREG_AUDIENCE,
        "sub": Uuid::new_v4().to_string(),
        "registry_principal": principal,
        "scope": scope,
        "registry_actor_kind": "human"
    }))
}

fn runtime_config(root: &std::path::Path, casework: &Url) -> Value {
    json!({
        "apiVersion":registry_breg::runtime_config::RUNTIME_CONFIG_API_VERSION,
        "kind":registry_breg::runtime_config::RUNTIME_CONFIG_KIND,
        "listener":{"bind":"127.0.0.1:8080"},
        "identity":{"environment":"local","instanceId":"composed-review","databaseId":Uuid::new_v4().to_string(),"databaseInitializationEnvironment":"local"},
        "secretProviders":{"file":{"root":root}},
        "database":{"runtimeUrlRef":"secret:file/database","migrationUrlRef":"secret:file/migration","pool":{"maxSize":4,"waitTimeoutMilliseconds":1000,"createTimeoutMilliseconds":1000,"recycleTimeoutMilliseconds":1000},"roles":{"migration":"registry_migration","runtime":"registry_runtime"}},
        "package":{"root":root,"trustAnchorPath":root.join("anchor"),"compilerSourceRevision":"test-source","activeRevision":PACKAGE_REVISION,"activeSequence":1},
        "authentication":{"oidc":{"issuer":"https://issuer.example","audience":BREG_AUDIENCE,"allowedAlgorithm":"EdDSA","accessTokenType":"JWT","scopeClaim":"scope","scopeSeparator":" ","allowedClients":["registry-client"],"deniedKids":[],"maxTokenLifetimeSeconds":300,"leewayMilliseconds":60000,"jwksCache":{"cacheTtlSeconds":600,"negativeCacheTtlSeconds":60,"refreshCooldownSeconds":30,"maxDocumentBytes":65536,"requestTimeoutMilliseconds":5000,"outageToleranceSeconds":900}},"authorityClaims":{"principal":"registry_principal"}},
        "audit":{"hashKeyRef":"secret:file/audit"},
        "cursor":{"secretRef":"secret:file/cursor","maxAgeSeconds":300},
        "eventDestinations":{},
        "reviewAuthorities":{"casework-a":{"endpoint":casework.as_str(),"profile":"producer","tokenRef":"secret:file/review-token","producerId":"registry-producer","recoveryDays":7}},
        "operationalTimeouts":{"httpRequestMilliseconds":10000,"shutdownGraceMilliseconds":30000,"recordLockMilliseconds":5000,"migrationLockMilliseconds":30000,"migrationStatementMilliseconds":60000}
    })
}

async fn wait_for(
    database: &tokio_postgres::Client,
    query: &str,
    expected: &str,
) -> tokio_postgres::Row {
    for _ in 0..100 {
        if let Some(row) = database.query_opt(query, &[]).await.expect("poll query") {
            if row.get::<_, String>(0) == expected {
                return row;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {expected}");
}

async fn request_json(
    endpoint: &Url,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
    key: Option<&str>,
    if_match: Option<&str>,
) -> (StatusCode, Value) {
    let client = reqwest::Client::new();
    let mut request = client
        .request(method, endpoint.join(path).expect("request URL"))
        .bearer_auth(bearer);
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    if let Some(if_match) = if_match {
        request = request.header("if-match", if_match);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.expect("HTTP response");
    let status = response.status();
    let bytes = response.bytes().await.expect("bounded test body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)}))
    };
    (status, body)
}

fn action(body: &Value, operation: &str) -> (String, String) {
    let selected = body["data"]["request"]["actions"]
        .as_array()
        .expect("request actions")
        .iter()
        .find(|candidate| candidate["operation"] == operation)
        .unwrap_or_else(|| panic!("missing {operation}: {body}"));
    (
        selected["href"].as_str().expect("action href").to_owned(),
        selected["ifMatch"]
            .as_str()
            .expect("action If-Match")
            .to_owned(),
    )
}

async fn approve_two_stage_review(
    casework_db: &tokio_postgres::Client,
    casework: &CaseworkService,
    idp: &MockIdp,
    review_request_id: Uuid,
    reviewer_token: &str,
    key_prefix: &str,
) {
    for (index, (subject, profile_id)) in [
        ("reviewer-one", "first-reviewer"),
        ("reviewer-two", "second-reviewer"),
    ]
    .into_iter()
    .enumerate()
    {
        let row = casework_db
            .query_one(
                "SELECT task_id,revision FROM casework_review_tasks
                 WHERE request_id=$1 AND stage_index=$2",
                &[&review_request_id, &(index as i32)],
            )
            .await
            .expect("review stage task");
        let task_id: Uuid = row.get(0);
        let revision: i64 = row.get(1);
        let actor = ActorContext {
            principal: IssuerPrincipal {
                issuer: idp.issuer(),
                subject: subject.to_owned(),
            },
            profile_id: profile_id.to_owned(),
            role: CaseworkRole::Staff,
        };
        casework
            .claim_review_task(
                &actor,
                task_id,
                Some("casework-reviewer"),
                reviewer_token,
                revision,
                &format!("{key_prefix}-claim-{index}"),
            )
            .await
            .expect("claim exact stage");
        casework
            .decide_review_task(
                &actor,
                task_id,
                ReviewTaskDecisionRequest {
                    decision: ReviewerDecisionKind::Approve,
                },
                Some("casework-reviewer"),
                reviewer_token,
                revision + 1,
                &format!("{key_prefix}-approve-{index}"),
            )
            .await
            .expect("approve exact stage");
    }
    let status: String = casework_db
        .query_one(
            "SELECT status FROM casework_review_results WHERE request_id=$1",
            &[&review_request_id],
        )
        .await
        .expect("terminal review result")
        .get(0);
    assert_eq!(status, "approved");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn breg_casework_two_stage_review_manual_apply_and_lost_receipt_recovery() {
    let idp = MockIdp::start().await;
    let breg_endpoint = Arc::new(Mutex::new(None));
    let (casework_app, casework, casework_db, casework_schema) = casework_fixture(
        &idp,
        BregReviewSource {
            endpoint: Arc::clone(&breg_endpoint),
            reader_token: token(
                &idp,
                BREG_AUDIENCE,
                "casework-source-reader",
                "breg:review-read",
            ),
        },
        casework_project(&idp.issuer()),
    )
    .await;
    let (casework_url, casework_task) = serve(casework_app).await;

    let registry = Arc::new(breg_project());
    let mut database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("BReg schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: REGISTRY_ID,
            environment: "local",
            instance_id: "composed-review",
            database_id: "composed-review-database",
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("BReg identity");
    drop(migration);
    migration_task.abort();

    let scratch = tempfile::tempdir().expect("runtime binding directory");
    std::fs::write(
        scratch.path().join("review-token"),
        token(
            &idp,
            CASEWORK_AUDIENCE,
            "registry-service",
            "casework:producer breg:review-read",
        ),
    )
    .expect("review token");
    for name in ["database", "migration", "audit", "cursor"] {
        std::fs::write(scratch.path().join(name), "unused-test-secret").unwrap();
    }
    for name in ["review-token", "database", "migration", "audit", "cursor"] {
        std::fs::set_permissions(
            scratch.path().join(name),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let config = parse_runtime_config(&runtime_config(scratch.path(), &casework_url).to_string())
        .expect("BReg runtime binding");
    let authorities = config
        .activate_review_authorities(&registry)
        .expect("review authority activation")
        .expect("review authority required");

    let normal_service = breg_service(
        &database,
        registry.clone(),
        identity.clone(),
        Arc::clone(&authorities),
        None,
    );
    let fault_service = breg_service(
        &database,
        registry.clone(),
        identity.clone(),
        Arc::clone(&authorities),
        Some(MutationFaultPoint::AfterCommitBeforeResponseRelease),
    );
    let (normal_url, normal_task) = serve(breg_router(normal_service, &registry, &idp)).await;
    let (fault_url, fault_task) = serve(breg_router(fault_service, &registry, &idp)).await;
    *breg_endpoint.lock().expect("BReg endpoint lock") = Some(normal_url.clone());

    let steward = token(&idp, BREG_AUDIENCE, "steward", "breg:steward");
    let submitter = token(&idp, BREG_AUDIENCE, "submitter", "breg:submit");
    let reviewer = token(&idp, BREG_AUDIENCE, "casework-reviewer", "breg:review-read");
    let applier = token(&idp, BREG_AUDIENCE, "manual-applier", "breg:apply");
    let (status, asset) = request_json(
        &normal_url,
        Method::POST,
        "/v1/records/assets?accessProfile=steward",
        &steward,
        Some(json!({"data":{"owner":"owner-a","label":"old"}})),
        Some("create-asset"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{asset}");
    let asset_id = asset["data"]["recordIdentifier"].as_str().unwrap();
    let (status, request) = request_json(
        &normal_url,
        Method::POST,
        "/v1/records/correction-requests?accessProfile=submitter",
        &submitter,
        Some(json!({"data":{"owner":"owner-a","asset":asset_id,"label":"approved"}})),
        Some("create-request"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    let request_id = request["data"]["recordIdentifier"].as_str().unwrap();
    let request_path =
        format!("/v1/records/correction-requests/{request_id}?accessProfile=submitter");
    let (status, draft) = request_json(
        &normal_url,
        Method::GET,
        &request_path,
        &submitter,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{draft}");
    let (submit_href, submit_etag) = action(&draft, "submit_request");
    let (status, submitted) = request_json(
        &normal_url,
        Method::POST,
        &submit_href,
        &submitter,
        Some(json!({})),
        Some("submit-request"),
        Some(&submit_etag),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{submitted}");
    let proposal_version = submitted["request"]["proposalVersion"].as_u64().unwrap();
    let effect_digest = submitted["request"]["effectDigest"]
        .as_str()
        .unwrap()
        .to_owned();

    let worker_pool = database.runtime_config.build_pool().expect("worker pool");
    assert!(
        run_review_authority_once_for_test(&worker_pool, &authorities)
            .await
            .expect("one review submission exchange"),
        "the pending review submission is claimed"
    );
    let accepted = wait_for(
        &database.admin,
        "SELECT state,accepted_binding::text FROM registry_internal.registry_request_review_submissions LIMIT 1",
        "accepted",
    )
    .await;
    let accepted_binding: Value =
        serde_json::from_str(&accepted.get::<_, String>(1)).expect("accepted binding");
    let review_request_id =
        Uuid::parse_str(accepted_binding["requestId"].as_str().unwrap()).unwrap();
    let stored_digest: String = database
        .admin
        .query_one(
            "SELECT expected_submission_digest FROM registry_internal.registry_request_review_submissions",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(accepted_binding["submissionDigest"], stored_digest);

    approve_two_stage_review(
        &casework_db,
        &casework,
        &idp,
        review_request_id,
        &reviewer,
        "primary",
    )
    .await;

    let (status, unchanged_asset) = request_json(
        &normal_url,
        Method::GET,
        &format!("/v1/records/assets/{asset_id}?accessProfile=steward"),
        &steward,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{unchanged_asset}");
    assert_eq!(unchanged_asset["data"]["domainData"]["label"], "old");

    let applier_path =
        format!("/v1/records/correction-requests/{request_id}?accessProfile=manual-applier");
    let (status, approved) = request_json(
        &normal_url,
        Method::GET,
        &applier_path,
        &applier,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let (apply_href, apply_etag) = action(&approved, "apply_request");
    let application_body = json!({
        "proposalVersion": proposal_version,
        "effectDigest": effect_digest
    });
    let (substituted_status, substituted) = request_json(
        &normal_url,
        Method::POST,
        &apply_href,
        &applier,
        Some(json!({
            "proposalVersion": proposal_version,
            "effectDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        })),
        Some("apply-substituted-digest"),
        Some(&apply_etag),
    )
    .await;
    assert_eq!(
        substituted_status,
        StatusCode::PRECONDITION_FAILED,
        "{substituted}"
    );

    let (status, race_asset) = request_json(
        &normal_url,
        Method::POST,
        "/v1/records/assets?accessProfile=steward",
        &steward,
        Some(json!({"data":{"owner":"owner-race","label":"old-race"}})),
        Some("create-race-asset"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{race_asset}");
    let race_asset_id = race_asset["data"]["recordIdentifier"].as_str().unwrap();
    let (status, race_request) = request_json(
        &normal_url,
        Method::POST,
        "/v1/records/correction-requests?accessProfile=submitter",
        &submitter,
        Some(json!({"data":{"owner":"owner-race","asset":race_asset_id,"label":"race-approved"}})),
        Some("create-race-request"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{race_request}");
    let race_request_id = race_request["data"]["recordIdentifier"].as_str().unwrap();
    let race_submitter_path =
        format!("/v1/records/correction-requests/{race_request_id}?accessProfile=submitter");
    let (status, race_draft) = request_json(
        &normal_url,
        Method::GET,
        &race_submitter_path,
        &submitter,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{race_draft}");
    let (race_submit_href, race_submit_etag) = action(&race_draft, "submit_request");
    let (status, race_submitted) = request_json(
        &normal_url,
        Method::POST,
        &race_submit_href,
        &submitter,
        Some(json!({})),
        Some("submit-race-request"),
        Some(&race_submit_etag),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{race_submitted}");
    let race_proposal_version = race_submitted["request"]["proposalVersion"]
        .as_u64()
        .unwrap();
    let race_effect_digest = race_submitted["request"]["effectDigest"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        run_review_authority_once_for_test(&worker_pool, &authorities)
            .await
            .expect("race review submission exchange")
    );
    let race_accepted: Value = database
        .admin
        .query_one(
            "SELECT accepted_binding FROM registry_internal.registry_request_review_submissions
              WHERE request_entity_id='correction-request' AND request_id=$1",
            &[&Uuid::parse_str(race_request_id).unwrap()],
        )
        .await
        .expect("race accepted binding")
        .get(0);
    let race_review_request_id =
        Uuid::parse_str(race_accepted["requestId"].as_str().unwrap()).unwrap();
    approve_two_stage_review(
        &casework_db,
        &casework,
        &idp,
        race_review_request_id,
        &reviewer,
        "race",
    )
    .await;

    let (status, race_owner_view) = request_json(
        &normal_url,
        Method::GET,
        &race_submitter_path,
        &submitter,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{race_owner_view}");
    let (race_cancel_href, race_cancel_etag) = action(&race_owner_view, "cancel_request");
    let race_applier_path =
        format!("/v1/records/correction-requests/{race_request_id}?accessProfile=manual-applier");
    let (status, race_applier_view) = request_json(
        &normal_url,
        Method::GET,
        &race_applier_path,
        &applier,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{race_applier_view}");
    let (race_apply_href, race_apply_etag) = action(&race_applier_view, "apply_request");
    let cancel = request_json(
        &normal_url,
        Method::POST,
        &race_cancel_href,
        &submitter,
        Some(json!({})),
        Some("race-cancel"),
        Some(&race_cancel_etag),
    );
    let apply = request_json(
        &normal_url,
        Method::POST,
        &race_apply_href,
        &applier,
        Some(json!({
            "proposalVersion":race_proposal_version,
            "effectDigest":race_effect_digest,
        })),
        Some("race-apply"),
        Some(&race_apply_etag),
    );
    let ((cancel_status, cancel_body), (apply_status, apply_body)) = tokio::join!(cancel, apply);
    assert!(
        (cancel_status == StatusCode::OK && apply_status == StatusCode::PRECONDITION_FAILED)
            || (cancel_status == StatusCode::PRECONDITION_FAILED && apply_status == StatusCode::OK),
        "cancel={cancel_status} {cancel_body}; apply={apply_status} {apply_body}"
    );
    let (status, race_final) = request_json(
        &normal_url,
        Method::GET,
        &race_submitter_path,
        &submitter,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{race_final}");
    let race_final_state = race_final["data"]["request"]["bregState"].as_str().unwrap();
    assert!(matches!(race_final_state, "cancelled" | "applied"));
    let (status, race_target) = request_json(
        &normal_url,
        Method::GET,
        &format!("/v1/records/assets/{race_asset_id}?accessProfile=steward"),
        &steward,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{race_target}");
    assert_eq!(
        race_target["data"]["domainData"]["label"],
        if race_final_state == "applied" {
            "race-approved"
        } else {
            "old-race"
        }
    );

    let (lost_status, _) = request_json(
        &fault_url,
        Method::POST,
        &apply_href,
        &applier,
        Some(application_body.clone()),
        Some("apply-reviewed-request"),
        Some(&apply_etag),
    )
    .await;
    assert_eq!(lost_status, StatusCode::SERVICE_UNAVAILABLE);
    casework_task.abort();
    let (recovered_status, recovered) = request_json(
        &normal_url,
        Method::POST,
        &apply_href,
        &applier,
        Some(application_body),
        Some("apply-reviewed-request"),
        Some(&apply_etag),
    )
    .await;
    assert_eq!(recovered_status, StatusCode::OK, "{recovered}");
    assert_eq!(recovered["request"]["bregState"], "applied");
    assert_eq!(recovered["request"]["proposalVersion"], proposal_version);
    assert_eq!(recovered["request"]["effectDigest"], effect_digest);

    let (status, applied_asset) = request_json(
        &normal_url,
        Method::GET,
        &format!("/v1/records/assets/{asset_id}?accessProfile=steward"),
        &steward,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied_asset}");
    assert_eq!(applied_asset["data"]["domainData"]["label"], "approved");

    // Casework's outer creation tombstone is intentionally bounded. Once it
    // expires, Casework may accept the same source proposal under a fresh
    // request ID, but the source must never replace its durable correlation
    // with that later request. Expire the complete Casework retention closure,
    // create and approve that fresh request, then prove BReg refuses its exact
    // accepted/result pair because it is not the source-pinned binding.
    let now = chrono::Utc::now();
    casework_db
        .execute(
            "UPDATE casework_review_results
                SET completed_at=$2,available_until=$3 WHERE request_id=$1",
            &[
                &review_request_id,
                &(now - chrono::TimeDelta::days(2)),
                &(now - chrono::TimeDelta::days(1)),
            ],
        )
        .await
        .expect("expire the original Casework result");
    casework_db
        .execute(
            "UPDATE casework_review_terminal_events
                SET completed_at=$2,retained_until=$3 WHERE request_id=$1",
            &[
                &review_request_id,
                &(now - chrono::TimeDelta::days(2)),
                &(now - chrono::TimeDelta::days(1)),
            ],
        )
        .await
        .expect("expire the original Casework terminal event");
    casework_db
        .execute(
            "UPDATE casework_review_requests
                SET terminal_at=$2,result_available_until=$3,accountability_retained_until=$3
              WHERE request_id=$1",
            &[
                &review_request_id,
                &(now - chrono::TimeDelta::days(2)),
                &(now - chrono::TimeDelta::days(1)),
            ],
        )
        .await
        .expect("expire the original Casework accountability tombstone");
    casework_db
        .execute(
            "UPDATE casework_review_accountability
                SET occurred_at=$2,retained_until=$3 WHERE request_id=$1",
            &[
                &review_request_id,
                &(now - chrono::TimeDelta::days(2)),
                &(now - chrono::TimeDelta::days(1)),
            ],
        )
        .await
        .expect("expire the original protected accountability rows");
    casework_db
        .execute(
            "UPDATE casework_review_submission_reservations
                SET retained_until=$2,recovery_deadline=$2 WHERE request_id=$1",
            &[&review_request_id, &(now - chrono::TimeDelta::seconds(1))],
        )
        .await
        .expect("expire the outer creation tombstone");
    casework
        .erase_expired_reviews()
        .await
        .expect("erase the expired outer Casework state");
    assert_eq!(
        casework_db
            .query_one(
                "SELECT count(*) FROM casework_review_requests WHERE request_id=$1",
                &[&review_request_id],
            )
            .await
            .expect("inspect erased original Casework request")
            .get::<_, i64>(0),
        0
    );

    let source_row = database
        .admin
        .query_one(
            "SELECT create_request,accepted_binding
               FROM registry_internal.registry_request_review_submissions
              WHERE request_entity_id='correction-request' AND request_id=$1",
            &[&Uuid::parse_str(request_id).unwrap()],
        )
        .await
        .expect("source-owned durable review correlation");
    let source_create: Value = source_row.get(0);
    let source_binding: Value = source_row.get(1);
    let source_create: ReviewCreateRequest =
        serde_json::from_value(source_create).expect("stored source review request");
    let source_binding: ReviewRequestAccepted =
        serde_json::from_value(source_binding).expect("stored accepted source correlation");
    assert_eq!(source_binding.request_id, review_request_id);
    let producer = ActorContext {
        principal: IssuerPrincipal {
            issuer: idp.issuer(),
            subject: "registry-service".to_owned(),
        },
        profile_id: "producer".to_owned(),
        role: CaseworkRole::Requester,
    };
    let replacement = casework
        .create_review_request(
            &producer,
            source_create,
            "replacement-after-outer-tombstone-expiry",
        )
        .await
        .expect("Casework may accept after its bounded outer tombstone expires")
        .accepted;
    assert_ne!(replacement.request_id, source_binding.request_id);
    approve_two_stage_review(
        &casework_db,
        &casework,
        &idp,
        replacement.request_id,
        &reviewer,
        "replacement",
    )
    .await;
    let replacement_result = match casework
        .review_result(&producer, replacement.request_id)
        .await
        .expect("read replacement result")
    {
        ReviewResultRead::Available(result) => *result,
        other => panic!("replacement review is not terminal: {other:?}"),
    };
    let transaction = database
        .admin
        .transaction()
        .await
        .expect("source correlation refusal transaction");
    let refusal = reconcile_result(
        &transaction,
        "casework-a",
        &replacement,
        &replacement_result,
    )
    .await
    .expect_err("a fresh Casework request cannot replace the source-pinned correlation");
    assert!(matches!(
        refusal,
        registry_breg::mutation::MutationError::PreconditionFailed
    ));
    transaction
        .rollback()
        .await
        .expect("rollback refused substitution probe");
    let pinned_after_refusal: Value = database
        .admin
        .query_one(
            "SELECT accepted_binding
               FROM registry_internal.registry_request_review_submissions
              WHERE request_entity_id='correction-request' AND request_id=$1",
            &[&Uuid::parse_str(request_id).unwrap()],
        )
        .await
        .expect("source correlation remains present")
        .get(0);
    assert_eq!(
        pinned_after_refusal["requestId"],
        source_binding.request_id.to_string()
    );

    normal_task.abort();
    fault_task.abort();
    database.cleanup().await;
    let (cleanup, cleanup_connection) =
        tokio_postgres::connect(&env::var("BREG_TEST_DATABASE_URL").unwrap(), NoTls)
            .await
            .unwrap();
    let cleanup_task = tokio::spawn(async move {
        let _ = cleanup_connection.await;
    });
    cleanup
        .batch_execute(&format!("DROP SCHEMA {casework_schema} CASCADE"))
        .await
        .unwrap();
    cleanup_task.abort();
}

/// The professional-review shape: every profile reads `registry_principal`,
/// the review stage excludes the initiator, and the producer trusts the shared
/// issuer for initiators. The person who submitted the change request in BReg
/// must then be refused when they try to claim or decide its review in
/// Casework, even though their token's `sub` is an unrelated provider id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn breg_submitter_cannot_claim_or_decide_their_own_excluded_review() {
    let idp = MockIdp::start().await;
    let breg_endpoint = Arc::new(Mutex::new(None));
    let mut project = casework_project(&idp.issuer());
    project.review_kinds[0].stages.truncate(1);
    project.review_kinds[0].stages[0].exclude_initiator = true;
    project.review_producers[0].trusted_initiator_issuer = Some(idp.issuer());
    let (casework_app, _casework, casework_db, casework_schema) = casework_fixture(
        &idp,
        BregReviewSource {
            endpoint: Arc::clone(&breg_endpoint),
            reader_token: token(
                &idp,
                BREG_AUDIENCE,
                "casework-source-reader",
                "breg:review-read",
            ),
        },
        project,
    )
    .await;
    casework_db
        .batch_execute(&format!(
            "INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind)
             VALUES('first-team','{issuer}','submitting-officer','staff'),
                   ('first-team','{issuer}','queue-supervisor','supervisor');",
            issuer = idp.issuer()
        ))
        .await
        .expect("the submitter also serves the review queue");
    let (casework_url, casework_task) = serve(casework_app).await;

    let registry = Arc::new(breg_project());
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("BReg schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: REGISTRY_ID,
            environment: "local",
            instance_id: "composed-review",
            database_id: "composed-review-database",
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("BReg identity");
    drop(migration);
    migration_task.abort();

    let scratch = tempfile::tempdir().expect("runtime binding directory");
    std::fs::write(
        scratch.path().join("review-token"),
        token(
            &idp,
            CASEWORK_AUDIENCE,
            "registry-service",
            "casework:producer breg:review-read",
        ),
    )
    .expect("review token");
    for name in ["database", "migration", "audit", "cursor"] {
        std::fs::write(scratch.path().join(name), "unused-test-secret").unwrap();
    }
    for name in ["review-token", "database", "migration", "audit", "cursor"] {
        std::fs::set_permissions(
            scratch.path().join(name),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let config = parse_runtime_config(&runtime_config(scratch.path(), &casework_url).to_string())
        .expect("BReg runtime binding");
    let authorities = config
        .activate_review_authorities(&registry)
        .expect("review authority activation")
        .expect("review authority required");
    let service = breg_service(
        &database,
        registry.clone(),
        identity,
        Arc::clone(&authorities),
        None,
    );
    let (breg_url, breg_task) = serve(breg_router(service, &registry, &idp)).await;
    *breg_endpoint.lock().expect("BReg endpoint lock") = Some(breg_url.clone());

    let steward = token(&idp, BREG_AUDIENCE, "steward", "breg:steward");
    // One person holds both roles: they may submit in BReg and they serve
    // the Casework queue that reviews their submission.
    let officer = human_token(
        &idp,
        "submitting-officer",
        "breg:submit casework:first-reviewer breg:review-read",
    );
    let colleague = human_token(
        &idp,
        "reviewer-one",
        "casework:first-reviewer breg:review-read",
    );
    let supervisor = human_token(
        &idp,
        "queue-supervisor",
        "casework:supervisor breg:review-read",
    );
    let (status, asset) = request_json(
        &breg_url,
        Method::POST,
        "/v1/records/assets?accessProfile=steward",
        &steward,
        Some(json!({"data":{"owner":"owner-a","label":"old"}})),
        Some("create-asset"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{asset}");
    let asset_id = asset["data"]["recordIdentifier"].as_str().unwrap();
    let (status, request) = request_json(
        &breg_url,
        Method::POST,
        "/v1/records/correction-requests?accessProfile=submitter",
        &officer,
        Some(json!({"data":{"owner":"owner-a","asset":asset_id,"label":"self-approved"}})),
        Some("create-request"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    let request_id = request["data"]["recordIdentifier"].as_str().unwrap();
    let (status, draft) = request_json(
        &breg_url,
        Method::GET,
        &format!("/v1/records/correction-requests/{request_id}?accessProfile=submitter"),
        &officer,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{draft}");
    let (submit_href, submit_etag) = action(&draft, "submit_request");
    let (status, submitted) = request_json(
        &breg_url,
        Method::POST,
        &submit_href,
        &officer,
        Some(json!({})),
        Some("submit-request"),
        Some(&submit_etag),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{submitted}");

    let worker_pool = database.runtime_config.build_pool().expect("worker pool");
    assert!(
        run_review_authority_once_for_test(&worker_pool, &authorities)
            .await
            .expect("one review submission exchange"),
        "the pending review submission is claimed"
    );
    let accepted = wait_for(
        &database.admin,
        "SELECT state,accepted_binding::text FROM registry_internal.registry_request_review_submissions LIMIT 1",
        "accepted",
    )
    .await;
    let accepted_binding: Value =
        serde_json::from_str(&accepted.get::<_, String>(1)).expect("accepted binding");
    let review_request_id =
        Uuid::parse_str(accepted_binding["requestId"].as_str().unwrap()).unwrap();
    let initiator = casework_db
        .query_one(
            "SELECT initiator_issuer,initiator_subject FROM casework_review_requests
             WHERE request_id=$1",
            &[&review_request_id],
        )
        .await
        .expect("recorded initiator");
    assert_eq!(initiator.get::<_, String>(0), idp.issuer());
    assert_eq!(initiator.get::<_, String>(1), "submitting-officer");
    let task_id: Uuid = casework_db
        .query_one(
            "SELECT task_id FROM casework_review_tasks WHERE request_id=$1",
            &[&review_request_id],
        )
        .await
        .expect("review task")
        .get(0);

    let casework_call =
        |bearer: &str, profile: &str, path: String, body: Option<Value>, key: &str| {
            let client = reqwest::Client::new();
            let mut call = client
                .post(casework_url.join(&path).expect("Casework URL"))
                .bearer_auth(bearer)
                .header(registry_casework_core::CASEWORK_PROFILE_HEADER, profile)
                .header(
                    registry_casework_core::SOURCE_PROFILE_HEADER,
                    "casework-reviewer",
                )
                .header("if-match", "\"1\"")
                .header("idempotency-key", key.to_owned());
            if let Some(body) = body {
                call = call.json(&body);
            }
            async move { call.send().await.expect("Casework response").status() }
        };
    assert_eq!(
        casework_call(
            &officer,
            "first-reviewer",
            format!("/v1/review-tasks/{task_id}/claim"),
            None,
            "self-claim",
        )
        .await,
        StatusCode::FORBIDDEN,
        "the submitter cannot claim the review of their own request"
    );
    assert_eq!(
        casework_call(
            &supervisor,
            "supervisor",
            format!("/v1/review-tasks/{task_id}/assign"),
            Some(json!({"assignee":{"issuer":idp.issuer(),"subject":"submitting-officer"}})),
            "assign-to-submitter",
        )
        .await,
        StatusCode::FORBIDDEN,
        "a supervisor cannot hand the review to the person who submitted it"
    );
    // The submitter never holds the task, so a decision is refused as a
    // conflict before any decision is recorded.
    assert_eq!(
        casework_call(
            &officer,
            "first-reviewer",
            format!("/v1/review-tasks/{task_id}/decisions"),
            Some(json!({"decision":{"type":"approve"}})),
            "self-decide",
        )
        .await,
        StatusCode::CONFLICT,
        "the submitter cannot decide the review of their own request"
    );
    let untouched: (String, i64, i64) = casework_db
        .query_one(
            "SELECT t.state,t.revision,
                    (SELECT count(*) FROM casework_review_decisions d WHERE d.request_id=t.request_id)
               FROM casework_review_tasks t WHERE t.task_id=$1",
            &[&task_id],
        )
        .await
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .expect("review task after refusal");
    assert_eq!(untouched, ("open".to_owned(), 1, 0));
    assert_eq!(
        casework_call(
            &colleague,
            "first-reviewer",
            format!("/v1/review-tasks/{task_id}/claim"),
            None,
            "colleague-claim",
        )
        .await,
        StatusCode::OK,
        "another member of the queue still claims the same task"
    );

    breg_task.abort();
    casework_task.abort();
    database.cleanup().await;
    let (cleanup, cleanup_connection) =
        tokio_postgres::connect(&env::var("BREG_TEST_DATABASE_URL").unwrap(), NoTls)
            .await
            .unwrap();
    let cleanup_task = tokio::spawn(async move {
        let _ = cleanup_connection.await;
    });
    cleanup
        .batch_execute(&format!("DROP SCHEMA {casework_schema} CASCADE"))
        .await
        .unwrap();
    cleanup_task.abort();
}

/// The professional-review Casework project exactly as `caseworkctl init`
/// writes it.
const PROFESSIONAL_REVIEW_TEMPLATE: &str =
    include_str!("../../registry-caseworkctl/templates/professional-review/casework.yaml");
/// The BReg professional-licences starter the template reviews.
const PROFESSIONAL_LICENCES_STARTER: &str =
    include_str!("../../../products/breg/starters/professional-licences/core/registry.yaml");
const STARTER_SOURCE_ID: &str = "professional-licences";
const STARTER_PURPOSE: &str = "starter-learning";

/// A person's or service's token from one named OAuth client, carrying the
/// deployment principal, purpose, and actor kind the starter profiles read.
fn client_token(
    idp: &MockIdp,
    client: &str,
    principal: &str,
    scope: &str,
    purpose: &str,
    actor_kind: &str,
) -> String {
    idp.mint_token(json!({
        "aud": BREG_AUDIENCE,
        "sub": Uuid::new_v4().to_string(),
        "azp": client,
        "registry_principal": principal,
        "scope": scope,
        "registry_purpose": purpose,
        "registry_actor_kind": actor_kind
    }))
}

/// The starter registry project with the casework-reader access profile
/// `caseworkctl source add` authors for the template's context projection.
/// The lifecycle hook that command also adds is left out: this journey
/// delivers reviews through the registry's review authority, not events.
fn starter_registry_with_casework_reader() -> Value {
    let mut project: Value =
        serde_norway::from_str(PROFESSIONAL_LICENCES_STARTER).expect("starter registry.yaml");
    project["accessProfiles"]
        .as_array_mut()
        .expect("starter access profiles")
        .push(json!({
            "id":"casework-reader","default":false,"principalClaim":"registry_principal",
            "requiredScopes":["casework:source-reader"],"requiredPurposes":["casework-sync"],
            "permissions":[{"entity":"scope-correction","operations":["get","list"],
                "readableFields":["authorization-conditions","licensed-activities","record","supporting-reference"],
                "readableRequestFields":["review_state"],"rowBoundaries":[]}]
        }));
    project
}

/// The source description `caseworkctl source add` writes: the
/// `bregctl explain change-requests` report for the registry directory,
/// narrowed to the one request entity the Casework project declares.
fn explained_source_description(registry_dir: &std::path::Path, entity: &str) -> Value {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(
        [
            std::ffi::OsString::from("bregctl"),
            "--format".into(),
            "json".into(),
            "explain".into(),
            "change-requests".into(),
            registry_dir.as_os_str().to_owned(),
        ],
        &mut stdout,
        &mut stderr,
    );
    let report: Value = serde_json::from_slice(&stdout).unwrap_or_else(|_| {
        panic!(
            "bregctl explain change-requests returned invalid JSON; stderr: {}",
            String::from_utf8_lossy(&stderr)
        )
    });
    assert_eq!(
        status,
        std::process::ExitCode::SUCCESS,
        "bregctl explain change-requests: {report}"
    );
    let request = report
        .pointer("/explanation/requests")
        .and_then(Value::as_array)
        .and_then(|requests| {
            requests
                .iter()
                .find(|candidate| candidate["requestEntity"] == entity)
        })
        .unwrap_or_else(|| panic!("explain omitted {entity}: {report}"))
        .clone();
    json!({
        "apiVersion":"registry.registrystack.org/casework-source-description/v1alpha1",
        "kind":"BRegCaseworkSourceDescription",
        "sourceId":STARTER_SOURCE_ID,
        "authority":"none",
        "origin":"bregctl explain change-requests",
        "sourceRevision":report["revision"],
        "request":request
    })
}

fn write_secret(root: &std::path::Path, name: &str, value: &str) {
    std::fs::write(root.join(name), value).expect("scratch secret");
    std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o600))
        .expect("scratch secret permissions");
}

/// POST a request as a Casework staff member reading the source through the
/// starter's reviewer profile.
async fn casework_staff_call(
    casework: &Url,
    bearer: &str,
    path: &str,
    body: Option<Value>,
    if_match: &str,
    key: &str,
) -> (StatusCode, Value) {
    let mut call = reqwest::Client::new()
        .post(casework.join(path).expect("Casework URL"))
        .bearer_auth(bearer)
        .header(registry_casework_core::CASEWORK_PROFILE_HEADER, "staff")
        .header(registry_casework_core::SOURCE_PROFILE_HEADER, "reviewer")
        .header("if-match", if_match)
        .header("idempotency-key", key);
    if let Some(body) = body {
        call = call.json(&body);
    }
    let response = call.send().await.expect("Casework response");
    let status = response.status();
    let bytes = response.bytes().await.expect("Casework body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)}))
    };
    (status, body)
}

/// The corrections inbox a staff member sees, reading the source through
/// the starter's reviewer profile.
async fn corrections_inbox(casework: &Url, bearer: &str) -> Value {
    let response = reqwest::Client::new()
        .get(
            casework
                .join("/v1/review-tasks?queue=corrections")
                .expect("inbox URL"),
        )
        .bearer_auth(bearer)
        .header(registry_casework_core::CASEWORK_PROFILE_HEADER, "staff")
        .header(registry_casework_core::SOURCE_PROFILE_HEADER, "reviewer")
        .send()
        .await
        .expect("inbox response");
    let status = response.status();
    let body: Value = response.json().await.expect("inbox body");
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

/// Run the review authority until the request's projected review result
/// reaches `expected`, making each pending result poll due first.
async fn reconcile_until(
    database: &TestDatabase,
    authorities: &Arc<registry_breg::review_store::ReviewAuthorityRegistry>,
    breg: &Url,
    path: &str,
    bearer: &str,
    expected: &str,
) -> Value {
    let pool = database.runtime_config.build_pool().expect("worker pool");
    let mut last = Value::Null;
    for _ in 0..50 {
        database
            .admin
            .batch_execute(
                "UPDATE registry_internal.registry_request_review_submissions
                 SET next_result_poll_at=transaction_timestamp()",
            )
            .await
            .expect("make the result poll due");
        run_review_authority_once_for_test(&pool, authorities)
            .await
            .expect("one review authority pass");
        let (status, body) = request_json(breg, Method::GET, path, bearer, None, None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        if body.pointer("/data/request/review/result/state") == Some(&json!(expected)) {
            return body;
        }
        last = body;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the review result never reconciled to {expected}: {last}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn professional_review_template_sends_back_revises_approves_and_applies() {
    let idp = MockIdp::start().await;
    // Every listener is bound first, so each service's configuration can
    // name the others' URLs before any service is built.
    let breg_listener = TcpListener::bind("127.0.0.1:0").await.expect("BReg");
    let casework_listener = TcpListener::bind("127.0.0.1:0").await.expect("Casework");
    let token_listener = TcpListener::bind("127.0.0.1:0").await.expect("token");
    let breg_url = Url::parse(&format!("http://{}/", breg_listener.local_addr().unwrap())).unwrap();
    let casework_url = Url::parse(&format!(
        "http://{}/",
        casework_listener.local_addr().unwrap()
    ))
    .unwrap();
    let token_url = Url::parse(&format!(
        "http://{}/oauth2/token",
        token_listener.local_addr().unwrap()
    ))
    .unwrap();

    // BReg: the starter plus the casework-reader profile, compiled in
    // process, and explained the way `caseworkctl source add` explains it.
    let registry_dir = tempfile::tempdir().expect("registry directory");
    let mut authored = starter_registry_with_casework_reader();
    // Every revise or rebase is captured so the draft reason BReg records
    // for the answer to the send-back is observable in the lifecycle event
    // it emits.
    authored["entities"]
        .as_array_mut()
        .expect("starter entities")
        .iter_mut()
        .find(|entity| entity["id"] == "scope-correction")
        .expect("scope-correction entity")["hooks"] = json!([{
        "phase":"after","id":"request-returned-to-draft","trigger":"request_lifecycle",
        "projection":["reason"],
        "when":{"kind":"request_lifecycle","transitions":["revise","rebase"],"toStates":["draft"]}
    }]);
    std::fs::write(
        registry_dir.path().join("registry.yaml"),
        serde_norway::to_string(&authored).expect("render registry.yaml"),
    )
    .expect("write registry.yaml");
    let registry = Arc::new(
        compile_project(
            &parse_project_json(&serde_json::to_vec(&authored).unwrap()).expect("starter parses"),
            &[],
            CompileProfile::Authoring,
        )
        .expect("starter compiles"),
    );
    // bregctl refuses a project path through a symbolic link, and the system
    // temporary directory can be one.
    let description = explained_source_description(
        &registry_dir
            .path()
            .canonicalize()
            .expect("registry directory path"),
        "scope-correction",
    );
    assert_eq!(
        description["sourceRevision"],
        registry.revision(),
        "the explained revision is the revision the running registry reports"
    );

    // Casework: the template exactly as written, with only the deployment
    // values a test cannot share with a real one replaced below.
    let mut project: CaseworkProject =
        serde_norway::from_str(PROFESSIONAL_REVIEW_TEMPLATE).expect("template parses");
    // The template names a local identity provider at a fixed port; this
    // journey's tokens come from a mock provider on an ephemeral port.
    project.review_producers[0].issuer = idp.issuer();
    // BReg names the submitting person with the issuer it verified their
    // token against, which is the same mock provider.
    project.review_producers[0].trusted_initiator_issuer = Some(idp.issuer());
    let project_root = tempfile::tempdir().expect("Casework project directory");
    std::fs::create_dir(project_root.path().join("sources")).unwrap();
    std::fs::write(
        project_root.path().join(&project.sources[0].description),
        serde_json::to_vec_pretty(&description).unwrap(),
    )
    .expect("source description");

    // The production BReg adapter, reading through casework-reader with a
    // private_key_jwt client of the test-local token route below.
    let casework_secrets = tempfile::tempdir().expect("Casework secrets");
    let generated_key = registry_platform_crypto::generate_private_jwk(
        registry_platform_crypto::GeneratedKeyAlgorithm::Es384,
    )
    .expect("reader key");
    // A private JWK serializes only its public members, so the secret file
    // restores the private scalar the adapter signs its assertions with.
    let mut reader_key = serde_json::to_value(&generated_key).unwrap();
    reader_key["d"] = json!(generated_key.d.clone().expect("private scalar"));
    write_secret(
        casework_secrets.path(),
        "reader-client-id",
        "casework-reader",
    );
    write_secret(
        casework_secrets.path(),
        "reader-key",
        &reader_key.take().to_string(),
    );
    write_secret(
        casework_secrets.path(),
        "webhook",
        "synthetic-webhook-secret-of-at-least-32-bytes",
    );
    let binding: registry_casework_breg::BregBinding = serde_json::from_value(json!({
        "baseUrl": breg_url.as_str(),
        "readerProfile": "casework-reader",
        "tokenEndpoint": token_url.as_str(),
        "clientIdRef": "secret:file/reader-client-id",
        "clientAssertionKeyRef": "secret:file/reader-key",
        "webhookSecretRef": "secret:file/webhook",
        "eventSource": "urn:registrystack:registry:professional-licences:instance:professional-licences-starter"
    }))
    .expect("BReg binding");
    let adapter = binding
        .build_adapter(
            &project.sources[0],
            project_root.path(),
            &SecretResolver::new([SecretProvider::File], casework_secrets.path())
                .expect("Casework secret resolver"),
        )
        .expect("production BReg adapter");
    // The token route issues the casework-reader service token for any
    // client assertion; the adapter's assertion itself is not under test.
    let reader_token = client_token(
        &idp,
        "casework-reader",
        "casework-source-reader",
        "casework:source-reader",
        "casework-sync",
        "service",
    );
    let token_app = Router::new().route(
        "/oauth2/token",
        axum::routing::post(move || {
            let reader_token = reader_token.clone();
            async move {
                axum::Json(json!({
                    "access_token": reader_token,
                    "token_type": "Bearer",
                    "expires_in": 300
                }))
            }
        }),
    );
    let (_, token_task) = serve_on(token_listener, token_app);

    let directory = format!(
        "INSERT INTO casework_teams(team_id,revision) VALUES('licence-corrections',1);
         INSERT INTO casework_queue_service(queue_id,team_id,revision)
         VALUES('corrections','licence-corrections',1);
         INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind)
         VALUES('licence-corrections','{issuer}','licence-reviewer','staff'),
               ('licence-corrections','{issuer}','scope-submitter','staff');",
        issuer = idp.issuer()
    );
    let (casework_app, _casework, casework_db, casework_schema) =
        casework_fixture_with_source(&idp, Arc::new(adapter), project, &directory).await;
    let (_, casework_task) = serve_on(casework_listener, casework_app);

    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("BReg schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: STARTER_SOURCE_ID,
            environment: "local",
            instance_id: "professional-licences-starter",
            database_id: "professional-licences-database",
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("BReg identity");
    drop(migration);
    migration_task.abort();

    let scratch = tempfile::tempdir().expect("runtime binding directory");
    write_secret(
        scratch.path(),
        "review-token",
        &token(
            &idp,
            CASEWORK_AUDIENCE,
            "professional-review-breg",
            "casework:reviews:request",
        ),
    );
    for name in ["database", "migration", "audit", "cursor"] {
        write_secret(scratch.path(), name, "unused-test-secret");
    }
    let mut runtime = runtime_config(scratch.path(), &casework_url);
    // The starter's review authority is `casework`, answered by the
    // template's `registry-breg` producer through `integration-requester`.
    runtime["reviewAuthorities"] = json!({"casework":{
        "endpoint":casework_url.as_str(),"profile":"integration-requester",
        "tokenRef":"secret:file/review-token","producerId":"registry-breg","recoveryDays":7
    }});
    let authorities = parse_runtime_config(&runtime.to_string())
        .expect("BReg runtime binding")
        .activate_review_authorities(&registry)
        .expect("review authority activation")
        .expect("review authority required");
    let service = breg_service(
        &database,
        registry.clone(),
        identity,
        Arc::clone(&authorities),
        None,
    );
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![BREG_AUDIENCE.to_owned()]);
    // The reviewer profile admits only the staff and supervisor clients, so
    // the verifier names every client this journey's tokens come from.
    verifier.allowed_clients = ["staff", "supervisor", "editor", "casework-reader"]
        .map(str::to_owned)
        .to_vec();
    let breg_app = breg_router_with(
        service,
        &registry,
        &idp,
        verifier,
        AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".to_owned())),
    );
    let (_, breg_task) = serve_on(breg_listener, breg_app);

    // One person submits in BReg through the editor client and also serves
    // the corrections queue through the staff client.
    let submitter = client_token(
        &idp,
        "editor",
        "scope-submitter",
        "starter:editor",
        STARTER_PURPOSE,
        "human",
    );
    let submitter_as_staff = client_token(
        &idp,
        "staff",
        "scope-submitter",
        "casework:staff starter:reviewer",
        STARTER_PURPOSE,
        "human",
    );
    let reviewer = client_token(
        &idp,
        "staff",
        "licence-reviewer",
        "casework:staff starter:reviewer",
        STARTER_PURPOSE,
        "human",
    );

    let (status, licence) = request_json(
        &breg_url,
        Method::POST,
        "/v1/records/professional-licenses?accessProfile=editor",
        &submitter,
        Some(json!({"data":{
            "localIdentifier":"licence-0001",
            "personReference":"person-0001",
            "regulatorReference":"regulator-0001",
            "jurisdictionReference":"jurisdiction-0001",
            "professionCode":"example-nursing",
            "licenceStatus":"recorded-active",
            "validFrom":"2026-01-01",
            "licensedActivities":["example-assessment"],
            "authorizationConditions":"Supervised practice only."
        }})),
        Some("create-licence"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{licence}");
    let licence_id = licence["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .to_owned();

    // 1. The submitter proposes a scope correction and submits it.
    let (status, created) = request_json(
        &breg_url,
        Method::POST,
        "/v1/records/scope-corrections?accessProfile=editor",
        &submitter,
        Some(json!({"data":{
            "record":licence_id,
            "licensedActivities":["example-assessment","example-advisory-services"],
            "authorizationConditions":"",
            "reason":"The advisory scope was recorded on paper but not entered.",
            "supportingReference":"board-minute-0001"
        }})),
        Some("create-correction"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let request_id = created["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .to_owned();
    let submitter_path = format!("/v1/records/scope-corrections/{request_id}?accessProfile=editor");
    let reviewer_path =
        format!("/v1/records/scope-corrections/{request_id}?accessProfile=reviewer");
    let (status, draft) = request_json(
        &breg_url,
        Method::GET,
        &submitter_path,
        &submitter,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{draft}");
    let (submit_href, submit_etag) = action(&draft, "submit_request");
    let (status, submitted) = request_json(
        &breg_url,
        Method::POST,
        &submit_href,
        &submitter,
        Some(json!({})),
        Some("submit-correction"),
        Some(&submit_etag),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{submitted}");

    // 2. The review authority delivers the submission to Casework.
    let worker_pool = database.runtime_config.build_pool().expect("worker pool");
    assert!(
        run_review_authority_once_for_test(&worker_pool, &authorities)
            .await
            .expect("one review submission exchange"),
        "the pending review submission is claimed"
    );
    let first_task: Uuid = casework_db
        .query_one("SELECT task_id FROM casework_review_tasks", &[])
        .await
        .expect("Casework opened one review task")
        .get(0);

    // 3. A different reviewer sees the task in the corrections inbox.
    let inbox = corrections_inbox(&casework_url, &reviewer).await;
    assert_eq!(
        inbox["items"]
            .as_array()
            .expect("inbox items")
            .iter()
            .map(|item| item["taskId"].clone())
            .collect::<Vec<_>>(),
        vec![json!(first_task)],
        "the reviewer's inbox shows the delivered review: {inbox}"
    );

    // 4. The submitter cannot claim the review of their own request.
    let (status, refusal) = casework_staff_call(
        &casework_url,
        &submitter_as_staff,
        &format!("/v1/review-tasks/{first_task}/claim"),
        None,
        "\"1\"",
        "self-claim",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");

    // 5. The reviewer claims it and sends it back.
    let (status, claimed) = casework_staff_call(
        &casework_url,
        &reviewer,
        &format!("/v1/review-tasks/{first_task}/claim"),
        None,
        "\"1\"",
        "claim-first",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    let (status, sent_back) = casework_staff_call(
        &casework_url,
        &reviewer,
        &format!("/v1/review-tasks/{first_task}/decisions"),
        Some(json!({"decision":{
            "type":"changes_requested",
            "outcome":"changes-requested",
            "reason":"Attach the board minute that records the advisory scope."
        }})),
        "\"2\"",
        "send-back-first",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{sent_back}");

    // 6. The send-back reconciles to BReg.
    reconcile_until(
        &database,
        &authorities,
        &breg_url,
        &submitter_path,
        &submitter,
        "changesRequested",
    )
    .await;

    // 7. The submitter revises the proposal and resubmits it.
    let (status, sent_back_view) = request_json(
        &breg_url,
        Method::GET,
        &submitter_path,
        &submitter,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent_back_view}");
    let (revise_href, revise_etag) = action(&sent_back_view, "revise_request");
    let advertised_rebase = sent_back_view["data"]["request"]["actions"]
        .as_array()
        .expect("request actions")
        .iter()
        .find(|candidate| candidate["operation"] == "revise_request")
        .map(|candidate| candidate["rebase"].clone())
        .expect("revise action");
    assert_eq!(
        advertised_rebase,
        json!(false),
        "a send-back is answered by a revision: {sent_back_view}"
    );
    let (status, revised) = request_json(
        &breg_url,
        Method::POST,
        &revise_href,
        &submitter,
        Some(json!({"rebase":advertised_rebase})),
        Some("revise-correction"),
        Some(&revise_etag),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revised}");
    let transitions: Vec<String> = database
        .admin
        .query(
            "SELECT payload FROM registry_internal.registry_outbox
              WHERE event_type='request-returned-to-draft' ORDER BY outbox_id",
            &[],
        )
        .await
        .expect("lifecycle events are readable")
        .iter()
        .map(|row| {
            let envelope: Value =
                serde_json::from_slice(&row.get::<_, Vec<u8>>(0)).expect("envelope is JSON");
            envelope["data"]["request"]["transition"]
                .as_str()
                .expect("recorded transition")
                .to_owned()
        })
        .collect();
    assert_eq!(
        transitions,
        ["revise"],
        "following the advertised action records a revision, not a rebase"
    );
    let draft_etag = reqwest::Client::new()
        .get(breg_url.join(&submitter_path).unwrap())
        .bearer_auth(&submitter)
        .send()
        .await
        .expect("revised draft")
        .headers()
        .get("etag")
        .expect("draft etag")
        .to_str()
        .unwrap()
        .to_owned();
    let patched = reqwest::Client::new()
        .patch(breg_url.join(&submitter_path).unwrap())
        .bearer_auth(&submitter)
        .header("content-type", "application/json-patch+json")
        .header("if-match", draft_etag)
        .header("idempotency-key", "patch-correction")
        .body(
            json!([{"op":"replace","path":"/data/supportingReference","value":"board-minute-0001-attached"}])
                .to_string(),
        )
        .send()
        .await
        .expect("patch response");
    assert_eq!(
        patched.status(),
        StatusCode::OK,
        "{}",
        patched.text().await.unwrap_or_default()
    );
    let (status, revised_draft) = request_json(
        &breg_url,
        Method::GET,
        &submitter_path,
        &submitter,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revised_draft}");
    let (submit_href, submit_etag) = action(&revised_draft, "submit_request");
    let (status, resubmitted) = request_json(
        &breg_url,
        Method::POST,
        &submit_href,
        &submitter,
        Some(json!({})),
        Some("resubmit-correction"),
        Some(&submit_etag),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resubmitted}");
    let mut second_task = None;
    // Revising a submitted request first withdraws its pending review, so
    // the resubmission reaches Casework on a later pass.
    for _ in 0..50 {
        run_review_authority_once_for_test(&worker_pool, &authorities)
            .await
            .expect("one review authority pass");
        second_task = casework_db
            .query_opt(
                "SELECT task_id FROM casework_review_tasks WHERE task_id<>$1",
                &[&first_task],
            )
            .await
            .expect("resubmission task query")
            .map(|row| row.get::<_, Uuid>(0));
        if second_task.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let submissions = database
        .admin
        .query(
            "SELECT state::text FROM registry_internal.registry_request_review_submissions",
            &[],
        )
        .await
        .expect("review submissions");
    let second_task = second_task.unwrap_or_else(|| {
        panic!(
            "Casework never opened a review task for the resubmission; submissions: {:?}",
            submissions
                .iter()
                .map(|row| row.get::<_, String>(0))
                .collect::<Vec<_>>()
        )
    });

    // 8. A reviewer approves the resubmission, and the approval reconciles.
    let inbox = corrections_inbox(&casework_url, &reviewer).await;
    assert_eq!(
        inbox["items"]
            .as_array()
            .expect("inbox items")
            .iter()
            .map(|item| item["taskId"].clone())
            .collect::<Vec<_>>(),
        vec![json!(second_task)],
        "the inbox shows only the resubmission's review: {inbox}"
    );
    let (status, claimed) = casework_staff_call(
        &casework_url,
        &reviewer,
        &format!("/v1/review-tasks/{second_task}/claim"),
        None,
        "\"1\"",
        "claim-second",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    let (status, approved) = casework_staff_call(
        &casework_url,
        &reviewer,
        &format!("/v1/review-tasks/{second_task}/decisions"),
        Some(json!({"decision":{"type":"approve"}})),
        "\"2\"",
        "approve-second",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{approved}");
    let approved = reconcile_until(
        &database,
        &authorities,
        &breg_url,
        &reviewer_path,
        &reviewer,
        "approved",
    )
    .await;

    // 9. onApproved is manual: the reviewer applies the approved request.
    let (apply_href, apply_etag) = action(&approved, "apply_request");
    let (status, applied) = request_json(
        &breg_url,
        Method::POST,
        &apply_href,
        &reviewer,
        Some(json!({
            "proposalVersion": approved["data"]["request"]["proposalVersion"],
            "effectDigest": approved["data"]["request"]["effectDigest"]
        })),
        Some("apply-correction"),
        Some(&apply_etag),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    let (status, corrected) = request_json(
        &breg_url,
        Method::GET,
        &format!("/v1/records/professional-licenses/{licence_id}?accessProfile=reviewer"),
        &reviewer,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{corrected}");
    assert_eq!(
        corrected["data"]["domainData"]["licensedActivities"],
        json!(["example-assessment", "example-advisory-services"])
    );

    breg_task.abort();
    casework_task.abort();
    token_task.abort();
    database.cleanup().await;
    let (cleanup, cleanup_connection) =
        tokio_postgres::connect(&env::var("BREG_TEST_DATABASE_URL").unwrap(), NoTls)
            .await
            .unwrap();
    let cleanup_task = tokio::spawn(async move {
        let _ = cleanup_connection.await;
    });
    cleanup
        .batch_execute(&format!("DROP SCHEMA {casework_schema} CASCADE"))
        .await
        .unwrap();
    cleanup_task.abort();
}
