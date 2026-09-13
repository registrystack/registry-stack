use super::*;
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use registry_casework_core::*;
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;

const ISSUER: &str = "https://task-token.test";
const SECRET: &[u8] = b"01234567890123456789012345678901";

fn binding() -> SourceBinding {
    SourceBinding {
        source_revision: "1".into(),
        version: "proposal-1".into(),
        integrity: None,
        generation: "generation-1".into(),
    }
}
struct Source {
    mode: Arc<AtomicUsize>,
}
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
        if self.mode.load(Ordering::SeqCst) == 5 {
            return Err(SourceAdapterError::Unavailable);
        }
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
        caller: Option<(&str, EphemeralCredential<'_>)>,
    ) -> Result<TaskSubjectContext, SourceAdapterError> {
        assert_eq!(fields, &["person-reference"]);
        match self.mode.load(Ordering::SeqCst) {
            1 => return Err(SourceAdapterError::Unavailable),
            3 if caller.is_some() => return Err(SourceAdapterError::Denied),
            4 if caller.is_none() => {
                tokio::time::sleep(std::time::Duration::from_millis(1250)).await
            }
            _ => (),
        }
        let person = if self.mode.load(Ordering::SeqCst) == 2 {
            "different-person"
        } else {
            "synthetic-person"
        };
        Ok(TaskSubjectContext {
            binding: binding(),
            values: std::collections::BTreeMap::from([("person-reference".into(), json!(person))]),
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

fn token(subject: &str, client: &str, kind: &str, scope: &str) -> String {
    token_claims(json!({"sub":subject,"azp":client,"registry_actor_kind":kind,"scope":scope}))
}
fn token_claims(mut claims: Value) -> String {
    let now = Utc::now().timestamp();
    let object = claims.as_object_mut().unwrap();
    object.insert("iss".into(), json!(ISSUER));
    object.entry("aud").or_insert(json!("urn:casework:test"));
    object.insert("iat".into(), json!(now));
    object.insert("exp".into(), json!(now + 300));
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test".into());
    header.typ = Some("at+jwt".into());
    encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap()
}
struct Fixture {
    app: Router,
    mode: Arc<AtomicUsize>,
    item: Uuid,
    profile_id: &'static str,
    template: TaskTemplate,
    admin: tokio_postgres::Client,
    schema: String,
    store: PostgresStore,
}
async fn fixture(lifetime: u64) -> Fixture {
    fixture_for_role(lifetime, CaseworkRole::Staff).await
}
async fn fixture_for_role(lifetime: u64, role: CaseworkRole) -> Fixture {
    let (profile_id, scope, membership_kind) = match role {
        CaseworkRole::Staff => ("staff", "casework:staff", "staff"),
        CaseworkRole::Supervisor => ("supervisor", "casework:supervisor", "supervisor"),
        CaseworkRole::Administrator | CaseworkRole::Requester => {
            panic!("task approval requires a staff or supervisor role")
        }
    };
    let base = std::env::var("CASEWORK_ASSIGNMENT_TEST_DATABASE_URL")
        .expect("disposable database is required");
    let schema = format!("task_http_{}", Uuid::new_v4().simple());
    let (admin, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let name = format!("CASEWORK_HTTP_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&name, &url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp").unwrap();
    let config = crate::DatabaseConfig {
        runtime_url_ref: format!("secret:env/{name}"),
        migration_url_ref: format!("secret:env/{name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let store = PostgresStore::connect_migration(&config, &secrets).unwrap();
    store.migrate().await.unwrap();
    std::env::remove_var(name);
    let template:TaskTemplate=serde_json::from_value(json!({"id":"summary","version":"1","label":"Prepare summary","eligibleTeams":["team"],"eligibleProfiles":[profile_id],"source":"source","itemKinds":["request"],"itemStates":["claimed"],"agent":{"issuer":ISSUER,"subject":"agent"},"client":"agent-client","resource":"urn:breg:test","purpose":"prepare-summary","scopes":["records:get"],"bounds":{"type":"breg","permissions":[{"collection":"people","operations":["get"]}]},"subjects":{"person_reference":"person-reference"},"lifetimeSeconds":lifetime})).unwrap();
    let project:CaseworkProject=serde_json::from_value(json!({"apiVersion":CASEWORK_API_VERSION,"kind":CASEWORK_KIND,"casework":{"id":"tasks","version":"1"},"accessProfiles":[{"id":profile_id,"principalClaim":"sub","requiredScopes":[scope],"role":profile_id}],"queues":[{"id":"review","label":"Review"}],"sources":[{"id":"source","adapter":"test","description":"Test source","requests":[{"entity":"request","queue":"review"}]}],"taskTemplates":[template]})).unwrap();
    let template = project.task_templates[0].clone();
    store
        .activate_task_templates(&project.task_templates)
        .await
        .unwrap();
    let db = store.client().await.unwrap();
    db.execute(
        "INSERT INTO casework_teams(team_id,revision) VALUES('team',1)",
        &[],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('team',$1,'human',$2)",&[&ISSUER,&membership_kind]).await.unwrap();
    db.execute(
        "INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('review','team',1)",
        &[],
    )
    .await
    .unwrap();
    let item = Uuid::new_v4();
    db.execute("INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,occurrence_kind,occurrence_key,binding,state,queue_id,holder_issuer,holder_subject,revision,first_observed_at,updated_at) VALUES($1,'source','request','request-1','review','review-1',$2,'claimed','review',$3,'human',1,now(),now())",&[&item,&serde_json::to_value(binding()).unwrap(),&ISSUER]).await.unwrap();
    let mode = Arc::new(AtomicUsize::new(0));
    let mut key = registry_platform_crypto::generate_private_jwk(
        registry_platform_crypto::GeneratedKeyAlgorithm::Rs384,
    )
    .unwrap();
    key.alg = Some("RS256".into());
    let authority = TaskAuthority {
        config: crate::TaskAuthorityConfig {
            id: "casework-tasks".into(),
            issuer: "https://task-authority.test".into(),
            exchange_audience: "https://issuer.test/token".into(),
            signing_key_ref: "secret:env/TEST_ONLY".into(),
            status_clients: std::collections::BTreeMap::from([
                ("breg-status".into(), "urn:breg:test".into()),
                ("other-resource".into(), "urn:other:test".into()),
            ]),
        },
        key,
        identifiers: registry_platform_audit::AuditKeyHasher::unkeyed_dev_only(),
    };
    let service = crate::CaseworkService::new(
        store.clone(),
        project.clone(),
        [Arc::new(Source { mode: mode.clone() }) as Arc<dyn SourceAdapter>],
    )
    .unwrap()
    .with_task_authority(Some(authority));
    let verifier = TokenVerifierConfig::access_token_profile(
        ISSUER,
        vec!["urn:casework:test".into()],
        vec![Algorithm::HS256],
        vec!["at+jwt".into()],
    )
    .with_scope_claim("scope")
    .with_allowed_clients(
        [
            "human-client",
            "agent-client",
            "other-agent",
            "breg-status",
            "other-resource",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    );
    let jwks=serde_json::from_value(json!({"keys":[{"kty":"oct","kid":"test","alg":"HS256","use":"sig","k":"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE"}]})).unwrap();
    let authenticator = crate::CaseworkAuthenticator::new(
        &project,
        verifier,
        Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())),
        crate::HumanIdentityConfig::default(),
    );
    let app = crate::router(crate::HttpState {
        service,
        authenticator: Arc::new(authenticator),
        project: Arc::new(project),
    });
    Fixture {
        app,
        mode,
        item,
        profile_id,
        template,
        admin,
        schema,
        store,
    }
}
async fn request(
    f: &Fixture,
    method: &str,
    path: &str,
    token: &str,
    human: bool,
    body: Option<Value>,
    key: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"));
    if human {
        req = req
            .header(CASEWORK_PROFILE_HEADER, f.profile_id)
            .header(SOURCE_PROFILE_HEADER, "source-reader");
    }
    if let Some(key) = key {
        req = req
            .header(IF_MATCH_HEADER, "\"1\"")
            .header(IDEMPOTENCY_KEY_HEADER, key);
    }
    let body = if let Some(body) = body {
        req = req.header("content-type", "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = f
        .app
        .clone()
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    assert!(response
        .headers()
        .get("cache-control")
        .is_some_and(|value| value.to_str().unwrap().contains("no-store")));
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn replace_membership(store: &PostgresStore, kind: &str) {
    let mut db = store.client().await.unwrap();
    let transaction = db.transaction().await.unwrap();
    transaction
        .execute(
            "UPDATE casework_memberships SET membership_kind=$1",
            &[&kind],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "UPDATE casework_meta SET directory_revision=directory_revision+1",
            &[],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

#[tokio::test]
async fn task_http_approval_assertion_status_and_revocation_enforce_current_authority() {
    let f = fixture(900).await;
    let human = token("human", "human-client", "human", "casework:staff");
    let agent = token("agent", "agent-client", "agent", "casework:grants:assert");
    let resource = token(
        "resource",
        "breg-status",
        "service",
        "casework:grants:status",
    );
    let base = format!("/v1/work-items/{}/task-grants", f.item);
    let preview = format!("/v1/work-items/{}/task-templates", f.item);
    let (status, body) = request(&f, "GET", &preview, &human, true, None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["templates"][0]["subjects"]["person_reference"],
        "synthetic-person"
    );
    let approval = json!({"templateId":"summary","templateVersion":"1"});
    let (status, body) = request(
        &f,
        "POST",
        &base,
        &human,
        true,
        Some(json!({"templateId":"summary","templateVersion":"1","resource":"urn:attacker"})),
        Some("extra-field"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    f.mode.store(3, Ordering::SeqCst);
    let (status, body) = request(
        &f,
        "POST",
        &base,
        &human,
        true,
        Some(approval.clone()),
        Some("approve"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    f.mode.store(0, Ordering::SeqCst);
    let (status, approved) = request(
        &f,
        "POST",
        &base,
        &human,
        true,
        Some(approval.clone()),
        Some("approve"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert!(approved.get("subjects").is_none());
    let id = approved["id"].as_str().unwrap();
    let assertion_path = format!("/v1/task-grants/{id}/assertion");
    let status_path = format!("/v1/task-grants/{id}/status");
    let (_, retried) = request(
        &f,
        "POST",
        &base,
        &human,
        true,
        Some(approval),
        Some("approve"),
    )
    .await;
    assert_eq!(
        retried, approved,
        "idempotent approval preserves identifier and deadline"
    );
    let wrong = token("agent", "other-agent", "agent", "casework:grants:assert");
    assert_eq!(
        request(&f, "POST", &assertion_path, &wrong, false, None, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&f, "POST", &assertion_path, &agent, true, None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let multi = token_claims(
        json!({"sub":"agent","azp":"agent-client","registry_actor_kind":"agent","scope":"casework:grants:assert","aud":["urn:casework:test","urn:breg:test"]}),
    );
    assert_eq!(
        request(&f, "POST", &assertion_path, &multi, false, None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, assertion) = request(&f, "POST", &assertion_path, &agent, false, None, None).await;
    assert_eq!(status, StatusCode::OK, "{assertion}");
    let raw = assertion["assertion"].as_str().unwrap();
    use base64::Engine;
    let (_, jwks) = request(
        &f,
        "GET",
        "/.well-known/jwks.json",
        &human,
        false,
        None,
        None,
    )
    .await;
    let keys = JwksFetcher::new_static(
        serde_json::from_value(jwks).unwrap(),
        JwksFetcherConfig::defaults(),
    );
    let verifier = registry_platform_oidc::TokenVerifier::new(
        TokenVerifierConfig::access_token_profile(
            "https://task-authority.test",
            vec!["https://issuer.test/token".into()],
            vec![Algorithm::RS256],
            vec!["JWT".into()],
        ),
        Arc::new(keys),
    );
    verifier
        .verify(raw)
        .await
        .expect("the returned assertion verifies against the served public keys");
    let payload: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(payload["registry_grant_exp"], approved["expiresAt"]);
    assert_eq!(payload["scope"], "records:get");
    assert_eq!(approved["scopes"], json!(["records:get"]));
    assert!(payload["exp"].as_u64().unwrap() - payload["iat"].as_u64().unwrap() <= 60);
    assert_eq!(payload["identity"]["person_reference"], "synthetic-person");
    assert_eq!(payload["sub"], "agent");
    let (status, active) = request(&f, "GET", &status_path, &resource, false, None, None).await;
    assert_eq!(status, StatusCode::OK, "{active}");
    assert_eq!(active["active"], true);
    assert_eq!(active["grant"]["grantId"], id);
    let other = token(
        "resource",
        "other-resource",
        "service",
        "casework:grants:status",
    );
    assert_eq!(
        request(&f, "GET", &status_path, &other, false, None, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    f.mode.store(1, Ordering::SeqCst);
    assert_eq!(
        request(&f, "POST", &assertion_path, &agent, false, None, None)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    f.mode.store(0, Ordering::SeqCst);
    assert_eq!(
        request(&f, "POST", &assertion_path, &agent, false, None, None)
            .await
            .0,
        StatusCode::OK,
        "temporary unavailability must not revoke"
    );
    f.mode.store(2, Ordering::SeqCst);
    assert_eq!(
        request(&f, "GET", &status_path, &resource, false, None, None)
            .await
            .1["active"],
        false
    );
    f.mode.store(0, Ordering::SeqCst);
    assert_eq!(
        request(&f, "GET", &status_path, &resource, false, None, None)
            .await
            .1["active"],
        false,
        "source selector regain must not revive grant"
    );
    let (status, second) = request(
        &f,
        "POST",
        &base,
        &human,
        true,
        Some(json!({"templateId":"summary","templateVersion":"1"})),
        Some("new-approval"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_ne!(second["id"], approved["id"]);
    let second_id = second["id"].as_str().unwrap();
    let revoke = format!("{base}/{second_id}/revoke");
    assert_eq!(
        request(&f, "POST", &revoke, &human, true, None, None)
            .await
            .0,
        StatusCode::OK
    );
    let second_status = format!("/v1/task-grants/{second_id}/status");
    assert_eq!(
        request(&f, "GET", &second_status, &resource, false, None, None)
            .await
            .1["active"],
        false
    );
    for extra in [
        json!({"act":{"sub":"human"}}),
        json!({"registry_grant_id":"forged"}),
    ] {
        let mut claims = json!({"sub":"agent","azp":"agent-client","registry_actor_kind":"agent","scope":"casework:grants:assert"});
        claims
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert_eq!(
            request(
                &f,
                "POST",
                &assertion_path,
                &token_claims(claims),
                false,
                None,
                None
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    let stored = f
        .store
        .task_grant(Uuid::parse_str(id).unwrap())
        .await
        .unwrap();
    assert!(stored.invalidated);
    f.admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", f.schema))
        .await
        .unwrap();
}

#[tokio::test]
async fn delegated_or_grant_bearing_human_tokens_cannot_approve_or_revoke_task_grants() {
    let f = fixture(900).await;
    let human = token("human", "human-client", "human", "casework:staff");
    let base = format!("/v1/work-items/{}/task-grants", f.item);
    let approval = json!({"templateId":"summary","templateVersion":"1"});
    let (status, grant) = request(
        &f,
        "POST",
        &base,
        &human,
        true,
        Some(approval.clone()),
        Some("valid-approval"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    let grant_id = grant["id"].as_str().unwrap();
    let revoke = format!("{base}/{grant_id}/revoke");

    for (key, extra) in [
        ("delegated-approval", json!({"act": {"sub": "agent"}})),
        (
            "grant-bearing-approval",
            json!({"registry_grant_id": "delegated-grant"}),
        ),
    ] {
        let mut claims = json!({
            "sub": "human",
            "azp": "human-client",
            "registry_actor_kind": "human",
            "scope": "casework:staff"
        });
        claims
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let credential = token_claims(claims);
        assert_eq!(
            request(
                &f,
                "POST",
                &base,
                &credential,
                true,
                Some(approval.clone()),
                Some(key),
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(&f, "POST", &revoke, &credential, true, None, None)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    assert!(
        !f.store
            .task_grant(Uuid::parse_str(grant_id).unwrap())
            .await
            .unwrap()
            .invalidated
    );
    f.admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", f.schema))
        .await
        .unwrap();
}

#[tokio::test]
async fn eligible_officer_can_revoke_without_holding_the_item_or_reading_the_source() {
    let f = fixture(900).await;
    let holder = token("human", "human-client", "human", "casework:staff");
    let base = format!("/v1/work-items/{}/task-grants", f.item);
    let (status, grant) = request(
        &f,
        "POST",
        &base,
        &holder,
        true,
        Some(json!({"templateId":"summary","templateVersion":"1"})),
        Some("approval-for-revocation"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    let grant_id = grant["id"].as_str().unwrap();
    let revoke = format!("{base}/{grant_id}/revoke");

    f.mode.store(5, Ordering::SeqCst);
    let outsider = token("outsider", "human-client", "human", "casework:staff");
    assert_eq!(
        request(&f, "POST", &revoke, &outsider, true, None, None)
            .await
            .0,
        StatusCode::FORBIDDEN,
        "a profile alone cannot revoke without eligible-team membership"
    );

    let db = f.store.client().await.unwrap();
    db.execute(
        "INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('team',$1,'revoker','staff')",
        &[&ISSUER],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE casework_meta SET directory_revision=directory_revision+1",
        &[],
    )
    .await
    .unwrap();

    let revoker = token("revoker", "human-client", "human", "casework:staff");
    let (status, body) = request(&f, "POST", &revoke, &revoker, true, None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["invalidated"], true);

    f.admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", f.schema))
        .await
        .unwrap();
}

#[tokio::test]
async fn supervisor_task_grant_requires_continued_supervisor_membership() {
    let f = fixture_for_role(900, CaseworkRole::Supervisor).await;
    let supervisor = token("human", "human-client", "human", "casework:supervisor");
    let agent = token("agent", "agent-client", "agent", "casework:grants:assert");
    let resource = token(
        "resource",
        "breg-status",
        "service",
        "casework:grants:status",
    );
    replace_membership(&f.store, "staff").await;
    let actor = ActorContext {
        principal: IssuerPrincipal {
            issuer: ISSUER.into(),
            subject: "human".into(),
        },
        profile_id: "supervisor".into(),
        role: CaseworkRole::Supervisor,
    };
    assert!(
        !f.store
            .eligible_task_template(&actor, f.item, &f.template)
            .await
            .unwrap(),
        "a supervisor profile cannot approve through staff membership"
    );
    replace_membership(&f.store, "supervisor").await;
    let approval_path = format!("/v1/work-items/{}/task-grants", f.item);
    let (status, grant) = request(
        &f,
        "POST",
        &approval_path,
        &supervisor,
        true,
        Some(json!({"templateId":"summary","templateVersion":"1"})),
        Some("supervisor-approval"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    let grant_id = grant["id"].as_str().unwrap();
    let assertion_path = format!("/v1/task-grants/{grant_id}/assertion");
    let status_path = format!("/v1/task-grants/{grant_id}/status");

    replace_membership(&f.store, "supervisor").await;
    assert_eq!(
        request(&f, "POST", &assertion_path, &agent, false, None, None)
            .await
            .0,
        StatusCode::OK,
        "an unchanged supervisor membership must preserve the grant"
    );
    let (status, active) = request(&f, "GET", &status_path, &resource, false, None, None).await;
    assert_eq!(status, StatusCode::OK, "{active}");
    assert_eq!(active["active"], true);

    replace_membership(&f.store, "staff").await;
    assert_eq!(
        request(&f, "POST", &assertion_path, &agent, false, None, None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, inactive) = request(&f, "GET", &status_path, &resource, false, None, None).await;
    assert_eq!(status, StatusCode::OK, "{inactive}");
    assert_eq!(inactive["active"], false);
    assert!(inactive.get("grant").is_none());
    let invalidation_reason: Option<String> = f
        .store
        .client()
        .await
        .unwrap()
        .query_one(
            "SELECT invalidation_reason FROM casework_task_grants WHERE grant_id=$1",
            &[&Uuid::parse_str(grant_id).unwrap()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(invalidation_reason.as_deref(), Some("eligibility"));
    replace_membership(&f.store, "supervisor").await;
    let (_, still_inactive) = request(&f, "GET", &status_path, &resource, false, None, None).await;
    assert_eq!(still_inactive["active"], false);

    f.admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", f.schema))
        .await
        .unwrap();
}

#[tokio::test]
async fn status_cannot_outlive_grant_deadline_during_source_read() {
    let f = fixture(1).await;
    let human = token("human", "human-client", "human", "casework:staff");
    let resource = token(
        "resource",
        "breg-status",
        "service",
        "casework:grants:status",
    );
    let path = format!("/v1/work-items/{}/task-grants", f.item);
    let (status, grant) = request(
        &f,
        "POST",
        &path,
        &human,
        true,
        Some(json!({"templateId":"summary","templateVersion":"1"})),
        Some("short-grant"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    f.mode.store(4, Ordering::SeqCst);
    let path = format!("/v1/task-grants/{}/status", grant["id"].as_str().unwrap());
    let (status, result) = request(&f, "GET", &path, &resource, false, None, None).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["active"], false);
    assert!(result.get("grant").is_none());
    f.admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", f.schema))
        .await
        .unwrap();
}
