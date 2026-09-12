//! Actual Casework approval -> native RFC 8693 exchange -> BREG PostgreSQL mutation.
//! Credentials and protected response bodies stay in memory and never enter logs or argv.
//! Set the two disposable database variables named by the ignore reason, then run
//! `cargo test --locked -p registry-casework --features postgres-test --lib
//! approved_casework_task_exchanges_on_stock_thunderid_and_revokes_breg_writes -- --ignored`.
use super::*;
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use registry_casework_core::*;
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use registry_thunderid_tooling::{container::Session, description::*, local, render};
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, path::Path, sync::Arc};
#[path = "native_resource.rs"]
mod resource;
const CASEWORK_RESOURCE: &str = "urn:casework:native-task";
const BREG_RESOURCE: &str = "urn:breg:task-test";
const AUTHORITY: &str = "https://casework.example";

fn binding() -> SourceBinding {
    SourceBinding {
        source_revision: "1".into(),
        version: "proposal-1".into(),
        integrity: None,
        generation: "generation-1".into(),
    }
}
/// Synthetic source fixture: only this governed selector is available.
struct Source;
#[async_trait]
impl SourceAdapter for Source {
    fn source_id(&self) -> &str {
        "source"
    }
    fn binding_generation(&self) -> &str {
        "generation-1"
    }
    async fn verify_transition(
        &self,
        _: EventRequest,
    ) -> Result<TransitionHint, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
    async fn read_authoritative(
        &self,
        _: &SubjectRef,
    ) -> Result<AuthoritativeObservation, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
    async fn discover_active(
        &self,
        _: Option<&DiscoveryCursor>,
        _: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
    async fn read_for_caller(
        &self,
        subject: &SubjectRef,
        _: &str,
        _: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        Ok(CallerSubjectView {
            display_reference: None,
            subject: subject.clone(),
            binding: binding(),
            disclosed: Default::default(),
            permitted_operations: Vec::new(),
        })
    }
    async fn read_task_context(
        &self,
        _: &SubjectRef,
        fields: &[String],
        _: Option<(&str, EphemeralCredential<'_>)>,
    ) -> Result<TaskSubjectContext, SourceAdapterError> {
        assert_eq!(fields, &["tenant"]);
        Ok(TaskSubjectContext {
            binding: binding(),
            values: std::collections::BTreeMap::from([("tenant".into(), json!("tenant-a"))]),
        })
    }
    async fn prepare_action(
        &self,
        _: PrepareActionRequest<'_>,
    ) -> Result<PreparedSourceAttempt, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
    async fn execute_prepared(
        &self,
        _: ExecutePreparedRequest<'_>,
    ) -> Result<SourceReceipt, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
}

fn key(kid: &str) -> registry_platform_crypto::PrivateJwk {
    let mut key = registry_platform_crypto::generate_private_jwk(
        registry_platform_crypto::GeneratedKeyAlgorithm::Rs384,
    )
    .unwrap();
    key.alg = Some("RS256".into());
    key.kid = Some(kid.into());
    key
}
fn client(
    id: &str,
    key: &registry_platform_crypto::PrivateJwk,
    kind: Option<&str>,
    scopes: &[&str],
) -> local::LocalClient {
    local::LocalClient {
        client_id: id.into(),
        public_jwks: json!({"keys":[key.public()]}).to_string(),
        claims: kind
            .map(|kind| BTreeMap::from([("registry_actor_kind".into(), kind.into())]))
            .unwrap_or_default(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        allow_human_fixture: kind == Some("human"),
    }
}
struct Issuer {
    description: IssuerDescription,
    image: String,
    jwks: Value,
}
impl Issuer {
    fn session(&self) -> Session<'_> {
        Session {
            label: &self.description.session.label,
            id: &self.description.session.id,
            port: self.description.port,
            state_root: &self.description.state_root,
            image: &self.image,
        }
    }
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.description.port)
    }
}
impl Drop for Issuer {
    fn drop(&mut self) {
        let _ = local::stop(&self.session(), Path::new("docker"));
    }
}
fn start_issuer(
    root: &Path,
    casework_port: u16,
    human: &registry_platform_crypto::PrivateJwk,
    agent: &registry_platform_crypto::PrivateJwk,
    status: &registry_platform_crypto::PrivateJwk,
    seed: &registry_platform_crypto::PrivateJwk,
) -> Issuer {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let id = Uuid::new_v4().to_string();
    let session = SessionIdentity {
        label: format!("institutional-task-{}", &id[..12]),
        id,
    };
    let mut description = local::local_description(
        session.clone(),
        port,
        root.into(),
        CASEWORK_RESOURCE.into(),
        vec![
            client("human-client", human, Some("human"), &["casework:staff"]),
            client(
                "task-agent",
                agent,
                Some("agent"),
                &["casework:grants:assert"],
            ),
            client(
                "breg-status",
                status,
                Some("service"),
                &["casework:grants:status"],
            ),
        ],
    )
    .unwrap();
    let mut seed_client = client("seed-client", seed, None, &["records:get"]);
    seed_client.claims = BTreeMap::from([
        ("tenant_claim".into(), "tenant-a".into()),
        ("registry_purpose".into(), "maintain".into()),
    ]);
    let target = local::local_description(
        SessionIdentity {
            label: session.label.clone(),
            id: Uuid::new_v4().to_string(),
        },
        port,
        root.into(),
        BREG_RESOURCE.into(),
        vec![seed_client],
    )
    .unwrap();
    description.resource_servers.extend(target.resource_servers);
    description.roles.extend(target.roles);
    description.machine_clients.extend(target.machine_clients);
    description
        .schema_attributes
        .extend(target.schema_attributes);
    description.schema_attributes.sort();
    description.schema_attributes.dedup();
    let authority_server = description.resource_servers[0].id.clone();
    description
        .machine_clients
        .iter_mut()
        .find(|c| c.client_id == "task-agent")
        .unwrap()
        .token_exchange = Some(TokenExchangeClient {
        assertion_resource_server_id: authority_server,
        assertion_scope: "casework:grants:assert".into(),
    });
    description.exchange_issuers.push(ExchangeIssuer {
        id: Uuid::new_v4().to_string(),
        name: "Casework task authority".into(),
        issuer: AUTHORITY.into(),
        jwks_endpoint: format!("http://host.docker.internal:{casework_port}/.well-known/jwks.json"),
    });
    std::fs::create_dir_all(root.join("secrets")).unwrap();
    for name in ["direct_auth_secret", "throwaway-bootstrap-password"] {
        let path = root.join("secrets").join(name);
        std::fs::write(&path, Uuid::new_v4().to_string()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    render::render(&description).unwrap();
    let pin = registry_thunderid_tooling::version::ThunderIdPin::load().unwrap();
    let mut issuer = Issuer {
        description,
        image: pin.image,
        jwks: Value::Null,
    };
    issuer.jwks = local::start(&issuer.session(), Path::new("docker"), &mut || false).unwrap();
    issuer
}
fn provider(
    issuer: &str,
    client: &str,
    key: &registry_platform_crypto::PrivateJwk,
    resource: &str,
    scope: &str,
) -> PrivateKeyJwt {
    PrivateKeyJwt::new(
        PrivateKeyJwtConfig::new(
            format!("{issuer}/oauth2/token").parse().unwrap(),
            client,
            key.clone(),
        )
        .with_audience(issuer)
        .with_resource(resource)
        .with_scopes([scope]),
    )
    .unwrap()
}
fn bearer(token: &registry_platform_httputil::BearerToken) -> String {
    token
        .authorization_header_value()
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned()
}
fn payload(token: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}
struct Fixture {
    app: Router,
    item: Uuid,
    admin: tokio_postgres::Client,
    schema: String,
}
async fn fixture(issuer: &Issuer, key: registry_platform_crypto::PrivateJwk) -> Fixture {
    let base = std::env::var("CASEWORK_ASSIGNMENT_TEST_DATABASE_URL")
        .expect("disposable Casework database required");
    let schema = format!("native_task_{}", Uuid::new_v4().simple());
    let (admin, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    admin
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let name = format!("NATIVE_TASK_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&name, url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp").unwrap();
    let db_config = crate::DatabaseConfig {
        runtime_url_ref: format!("secret:env/{name}"),
        migration_url_ref: format!("secret:env/{name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let store = PostgresStore::connect_migration(&db_config, &secrets).unwrap();
    store.migrate().await.unwrap();
    std::env::remove_var(name);
    let human = issuer
        .description
        .machine_clients
        .iter()
        .find(|c| c.client_id == "human-client")
        .unwrap()
        .agent_id
        .clone();
    let agent = issuer
        .description
        .machine_clients
        .iter()
        .find(|c| c.client_id == "task-agent")
        .unwrap()
        .agent_id
        .clone();
    let breg: Value = serde_json::from_str(resource::PROJECT).unwrap();
    let operations = breg["accessProfiles"][1]["permissions"][0]["operations"].clone();
    let template:TaskTemplate=serde_json::from_value(json!({"id":"draft","version":"1","label":"Prepare correction draft","eligibleTeams":["team"],"eligibleProfiles":["staff"],"source":"source","itemKinds":["request"],"itemStates":["claimed"],"agent":{"issuer":issuer.url(),"subject":agent},"client":"task-agent","resource":BREG_RESOURCE,"purpose":"review","scopes":["records:get"],"bounds":{"type":"breg","permissions":[{"collection":"correction-requests","operations":operations}]},"subjects":{"tenant_claim":"tenant"},"lifetimeSeconds":900})).unwrap();
    let project:CaseworkProject=serde_json::from_value(json!({"apiVersion":CASEWORK_API_VERSION,"kind":CASEWORK_KIND,"casework":{"id":"native-tasks","version":"1"},"accessProfiles":[{"id":"staff","principalClaim":"sub","requiredScopes":["casework:staff"],"role":"staff"}],"queues":[{"id":"review","label":"Review"}],"sources":[{"id":"source","adapter":"test","description":"Synthetic source","requests":[{"entity":"request","queue":"review"}]}],"taskTemplates":[template]})).unwrap();
    store
        .activate_task_templates(&project.task_templates)
        .await
        .unwrap();
    admin
        .execute(
            "INSERT INTO casework_teams(team_id,revision) VALUES('team',1)",
            &[],
        )
        .await
        .unwrap();
    admin.execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('team',$1,$2,'staff')",&[&issuer.url(),&human]).await.unwrap();
    admin.execute("INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('review','team',1)",&[]).await.unwrap();
    let item = Uuid::new_v4();
    admin.execute("INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,occurrence_kind,occurrence_key,binding,state,queue_id,holder_issuer,holder_subject,revision,first_observed_at,updated_at) VALUES($1,'source','request','synthetic-request','review','review-1',$2,'claimed','review',$3,$4,1,now(),now())",&[&item,&serde_json::to_value(binding()).unwrap(),&issuer.url(),&human]).await.unwrap();
    let authority = TaskAuthority {
        config: crate::TaskAuthorityConfig {
            id: "casework".into(),
            issuer: AUTHORITY.into(),
            exchange_audience: issuer.url(),
            signing_key_ref: "secret:env/UNUSED_IN_MEMORY_KEY".into(),
            status_clients: BTreeMap::from([("breg-status".into(), BREG_RESOURCE.into())]),
        },
        key,
    };
    let service = crate::CaseworkService::new(
        store,
        project.clone(),
        [Arc::new(Source) as Arc<dyn SourceAdapter>],
    )
    .unwrap()
    .with_task_authority(Some(authority));
    let verifier = TokenVerifierConfig::access_token_profile(
        issuer.url(),
        vec![CASEWORK_RESOURCE.into()],
        vec![jsonwebtoken::Algorithm::RS256],
        vec!["at+jwt".into()],
    )
    .with_scope_claim("scope")
    .with_allowed_clients(vec![
        "human-client".into(),
        "task-agent".into(),
        "breg-status".into(),
    ]);
    let auth = crate::CaseworkAuthenticator::new(
        &project,
        verifier,
        Arc::new(JwksFetcher::new_static(
            serde_json::from_value(issuer.jwks.clone()).unwrap(),
            JwksFetcherConfig::defaults(),
        )),
        crate::HumanIdentityConfig::default(),
    );
    Fixture {
        app: crate::router(crate::HttpState {
            service,
            authenticator: Arc::new(auth),
            project: Arc::new(project),
        }),
        item,
        admin,
        schema,
    }
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    human: bool,
    body: Option<Value>,
    key: Option<&str>,
) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"));
    if human {
        req = req
            .header(CASEWORK_PROFILE_HEADER, "staff")
            .header(SOURCE_PROFILE_HEADER, "source-reader");
    }
    if let Some(key) = key {
        req = req
            .header(IF_MATCH_HEADER, "\"1\"")
            .header(IDEMPOTENCY_KEY_HEADER, key);
    }
    let data = if let Some(body) = body {
        req = req.header("content-type", "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(req.body(data).unwrap()).await.unwrap();
    (
        response.status(),
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker plus disposable CASEWORK_ASSIGNMENT_TEST_DATABASE_URL and BREG_TEST_DATABASE_URL"]
async fn approved_casework_task_exchanges_on_stock_thunderid_and_revokes_breg_writes() {
    let root = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let casework_port = listener.local_addr().unwrap().port();
    let (human_key, agent_key, status_key, seed_key) =
        (key("human"), key("agent"), key("status"), key("seed"));
    let (h, a, s, d) = (
        human_key.clone(),
        agent_key.clone(),
        status_key.clone(),
        seed_key.clone(),
    );
    let path = root.path().to_path_buf();
    let issuer =
        tokio::task::spawn_blocking(move || start_issuer(&path, casework_port, &h, &a, &s, &d))
            .await
            .unwrap();
    let f = fixture(&issuer, key("casework-task-authority")).await;
    let serving = f.app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, serving).await.unwrap();
    });
    let human = bearer(
        &provider(
            &issuer.url(),
            "human-client",
            &human_key,
            CASEWORK_RESOURCE,
            "casework:staff",
        )
        .bearer_token()
        .await
        .unwrap(),
    );
    let base = format!("/v1/work-items/{}/task-grants", f.item);
    let (code, preview) = request(
        &f.app,
        "GET",
        &format!("/v1/work-items/{}/task-templates", f.item),
        &human,
        true,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(
        preview["templates"][0]["subjects"]["tenant_claim"],
        "tenant-a"
    );
    let (code, grant) = request(
        &f.app,
        "POST",
        &base,
        &human,
        true,
        Some(json!({"templateId":"draft","templateVersion":"1"})),
        Some("native-approval"),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let grant_id = grant["id"].as_str().unwrap();
    let bootstrap = bearer(
        &provider(
            &issuer.url(),
            "task-agent",
            &agent_key,
            CASEWORK_RESOURCE,
            "casework:grants:assert",
        )
        .bearer_token()
        .await
        .unwrap(),
    );
    assert!(payload(&bootstrap).get("registry_grant_id").is_none());
    let (code, issued) = request(
        &f.app,
        "POST",
        &format!("/v1/task-grants/{grant_id}/assertion"),
        &bootstrap,
        false,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let assertion = issued["assertion"].as_str().unwrap();
    let exchange = provider(
        &issuer.url(),
        "task-agent",
        &agent_key,
        BREG_RESOURCE,
        "records:get",
    );
    let token = bearer(&exchange.exchange(assertion).await.unwrap());
    let claims = payload(&token);
    assert_eq!(claims["registry_grant_id"], grant_id);
    assert_eq!(claims["registry_grant_source_issuer"], AUTHORITY);
    assert_eq!(claims["registry_grant_exp"], issued["grantExpiresAt"]);
    assert_eq!(claims["registry_grant_exp"], grant["expiresAt"]);
    assert_eq!(claims["identity"], json!({"tenant_claim":"tenant-a"}));
    assert_eq!(claims["registry_grant_bounds"], grant["bounds"]);
    assert_eq!(claims["scope"], "records:get");
    assert_eq!(claims["registry_purpose"], "review");
    assert_eq!(claims["registry_grant_client"], "task-agent");
    assert_eq!(claims["registry_grant_resource"], BREG_RESOURCE);
    assert!(claims["exp"].as_u64().unwrap() <= claims["iat"].as_u64().unwrap() + 300);
    let reexchanged = bearer(&exchange.exchange(&token).await.unwrap());
    let repeated = payload(&reexchanged);
    for name in [
        "registry_actor_kind",
        "registry_grant_id",
        "registry_grant_authority",
        "registry_grant_source_issuer",
        "registry_grant_client",
        "registry_grant_resource",
        "registry_grant_exp",
        "registry_grant_bounds",
        "registry_purpose",
        "identity",
        "scope",
    ] {
        assert_eq!(
            repeated[name], claims[name],
            "re-exchange must preserve {name}"
        );
    }
    let db = resource::TestDatabase::create(8).await;
    let registry = Arc::new(
        registry_breg::compile_project(
            &registry_breg::parse_project_json(resource::PROJECT.as_bytes()).unwrap(),
            &[],
            registry_breg::CompileProfile::Authoring,
        )
        .unwrap(),
    );
    let identity = resource::install(&db, &registry).await;
    let checker = Arc::new(
        registry_breg::task_grant::TaskGrantStatusClient::new(
            "casework".into(),
            AUTHORITY.into(),
            BREG_RESOURCE.into(),
            format!("http://127.0.0.1:{casework_port}").parse().unwrap(),
            Arc::new(provider(
                &issuer.url(),
                "breg-status",
                &status_key,
                CASEWORK_RESOURCE,
                "casework:grants:status",
            )),
            None,
        )
        .unwrap(),
    );
    let app = resource::app(
        &db,
        registry,
        identity,
        &issuer.url(),
        issuer.jwks.clone(),
        checker,
    );
    let seed = bearer(
        &provider(
            &issuer.url(),
            "seed-client",
            &seed_key,
            BREG_RESOURCE,
            "records:get",
        )
        .bearer_token()
        .await
        .unwrap(),
    );
    let old = resource::create(
        &app,
        "/v1/records/sites?accessProfile=steward",
        &seed,
        "old",
        json!({"tenant":"tenant-a","name":"old"}),
    )
    .await;
    let next = resource::create(
        &app,
        "/v1/records/sites?accessProfile=steward",
        &seed,
        "next",
        json!({"tenant":"tenant-a","name":"next"}),
    )
    .await;
    let placement = resource::create(
        &app,
        "/v1/records/placements?accessProfile=steward",
        &seed,
        "placement",
        json!({"tenant":"tenant-a","site":resource::id(&old)}),
    )
    .await;
    let draft=resource::create(&app,"/v1/records/correction-requests?accessProfile=submitter",&token,"native-draft",json!({"tenant":"tenant-a","placement":resource::id(&placement),"proposedSite":resource::id(&next),"reason":"Synthetic task correction"})).await;
    let id = resource::id(&draft);
    let read = resource::get(&app, &id, "submitter", &token).await;
    let before = resource::counts(&db).await;
    let (code, _) = request(
        &f.app,
        "POST",
        &format!("{base}/{grant_id}/revoke"),
        &human,
        true,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let refused = resource::send(
        &app,
        axum::http::Method::PATCH,
        &format!("/v1/records/correction-requests/{id}?accessProfile=submitter"),
        &token,
        Some("revoked-write"),
        Some(&read.etag),
        json!([{"op":"replace","path":"/data/reason","value":"Must not persist"}]),
    )
    .await;
    assert_eq!(refused.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(resource::counts(&db).await, before);
    let (code, _) = request(
        &f.app,
        "POST",
        &format!("/v1/task-grants/{grant_id}/assertion"),
        &bootstrap,
        false,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    drop(app);
    db.cleanup().await;
    server.abort();
    drop(f.app);
    f.admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", f.schema))
        .await
        .unwrap();
    tokio::task::spawn_blocking(move || drop(issuer))
        .await
        .unwrap();
}
