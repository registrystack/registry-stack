// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]

//! Consent enforcement against real PostgreSQL: every read operation of a
//! gated permission, for a permission gated on its own identity (`on: id`)
//! and one gated through a reference field (`on: person`), plus the ordering,
//! recipient, feed and catalog rules of the consent probe.

#[path = "support/consent_fixture.rs"]
#[allow(dead_code)]
mod consent_fixture;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use registry_breg::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    begin_record_transaction, initialize_compiled_registry_state_for_test, install_compiled_schema,
    verify_catalog_identity_for_catalog, ClaimContext, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, PostgresRecordMutationService, PostgresRecordReadService,
    PostgresRevisionReadService, PostgresSnapshotReadService, RegistryLockKey,
    RegistryStateTestIdentity, RuntimePool,
};
use registry_breg::CompiledRegistry;
use registry_platform_audit::AuditProfile;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tower::Service as _;
use zeroize::Zeroizing;

const AUDIENCE: &str = "urn:breg:consent";
const PACKAGE_ID: &str = "consent-access";
const WFP_CLIENT: &str = "wfp-scope";
const ALPHA_CLIENT: &str = "ngo-alpha-portal";
/// Admitted by the issuer but mapped to no recipient organization.
const STEWARD_CLIENT: &str = "steward-console";
const PURPOSE: &str = "food-assistance";
const SCOPE: &str = "food-targeting";

static IDEMPOTENCY: AtomicU64 = AtomicU64::new(0);

struct Harness {
    database: postgres_harness::TestDatabase,
    registry: Arc<CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    pool: RuntimePool,
    lock_key: RegistryLockKey,
    idp: MockIdp,
    app: axum::Router,
}

impl Harness {
    async fn start() -> Self {
        let registry = Arc::new(consent_fixture::compile(&consent_fixture::source()).unwrap());
        let database = postgres_harness::TestDatabase::create(4).await;
        let (migration, migration_task) = database.connect_migration().await;
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("generated consent schema installs");
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: PACKAGE_ID,
                environment: "local",
                instance_id: "consent-instance",
                database_id: "consent-database",
                package_revision: "consent-package-1",
                package_sequence: 1,
            },
        )
        .await
        .expect("consent catalog identity includes probe functions");
        migration_task.abort();
        let pool = database.runtime_config.build_pool().unwrap();
        let lock_key = RegistryLockKey::derive(PACKAGE_ID).unwrap();
        let audit = AuditProfile::production_from_secret_bytes(vec![0x5e; 32].into()).unwrap();
        let cursors = Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x4e; 32]), Duration::from_secs(300)).unwrap(),
        );
        let records = Arc::new(PostgresRecordReadService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            audit.clone(),
            cursors.clone(),
        ));
        let revisions = Arc::new(PostgresRevisionReadService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            audit.clone(),
        ));
        let snapshots = Arc::new(PostgresSnapshotReadService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            audit.clone(),
            cursors.clone(),
        ));
        let mutations = Arc::new(PostgresRecordMutationService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            audit,
        ));
        let service = Arc::new(
            HttpService::new(
                registry.clone(),
                ReadRuntimeIdentity {
                    package_revision: identity.package_revision.clone(),
                    schema_fingerprint: identity.schema_fingerprint.clone(),
                },
                records,
                Arc::new(AlwaysReady),
                cursors,
            )
            .with_postgres_revisions(revisions)
            .with_snapshots(snapshots)
            .with_postgres_mutations(mutations),
        );
        let idp = MockIdp::start().await;
        let key_source = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        ));
        let mut verifier = oidc_verifier_config(idp.issuer(), vec![AUDIENCE.into()]);
        verifier.allowed_clients = vec![
            WFP_CLIENT.into(),
            ALPHA_CLIENT.into(),
            STEWARD_CLIENT.into(),
        ];
        let authenticator = Arc::new(
            RegistryAuthenticator::new(
                &registry,
                verifier,
                key_source,
                AuthorityClaimConfig::new("principal", Some("purpose".into())),
            )
            .unwrap(),
        );
        let app = authenticated_router(service, authenticator);
        Self {
            database,
            registry,
            identity,
            pool,
            lock_key,
            idp,
            app,
        }
    }

    fn reader(&self, client: &str, purpose: &str) -> String {
        self.idp.mint_token(json!({
            "aud": AUDIENCE, "registry_actor_kind": "service", "principal": "reader",
            "scope": "records:read", "azp": client, "purpose": purpose,
        }))
    }

    fn feed(&self, client: &str) -> String {
        self.idp.mint_token(json!({
            "aud": AUDIENCE, "registry_actor_kind": "service", "principal": "feed-reader",
            "scope": "consent:read", "azp": client,
        }))
    }

    fn steward(&self) -> String {
        self.idp.mint_token(json!({
            "aud": AUDIENCE, "registry_actor_kind": "service", "principal": "steward",
            "scope": "records:manage", "azp": STEWARD_CLIENT,
        }))
    }

    async fn create(&self, route: &str, data: Value) -> String {
        let key = format!("create-{}", IDEMPOTENCY.fetch_add(1, Ordering::Relaxed));
        let (status, body) = send(
            &self.app,
            Method::POST,
            &format!("/v1/records/{route}?accessProfile=steward"),
            json!({"data": data}),
            Some(&key),
            &self.steward(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{route}: {body}");
        body["data"]["recordIdentifier"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn person(&self, name: &str) -> String {
        self.create("persons", json!({"givenName": name, "district": "north"}))
            .await
    }

    /// Record one consent decision through the steward action, the only
    /// path that creates consent rows.
    async fn decide(&self, decision: Decision<'_>) -> String {
        let mut input = json!({
            "subject": decision.subject,
            "recipient": decision.recipient,
            "purpose": decision.purpose,
            "scope": decision.scope,
            "decision": decision.decision,
            "effectiveAt": at(decision.from),
        });
        if let Some(until) = decision.until {
            input["expiresAt"] = json!(at(until));
        }
        let key = format!("decide-{}", IDEMPOTENCY.fetch_add(1, Ordering::Relaxed));
        let (status, body) = send(
            &self.app,
            Method::POST,
            "/v1/actions/record-consent?accessProfile=steward",
            json!({"input": input}),
            Some(&key),
            &self.steward(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["results"]["decision"]["recordId"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn status(&self, uri: &str, token: &str) -> StatusCode {
        send(&self.app, Method::GET, uri, Value::Null, None, token)
            .await
            .0
    }

    async fn get(&self, uri: &str, token: &str) -> Value {
        let (status, body) = send(&self.app, Method::GET, uri, Value::Null, None, token).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        body
    }

    /// Whether `person` is readable under `food-targeting` for this token.
    async fn sees(&self, person: &str, token: &str) -> bool {
        let status = self
            .status(
                &format!("/v1/records/persons/{person}?accessProfile={SCOPE}"),
                token,
            )
            .await;
        assert!(
            status == StatusCode::OK || status == StatusCode::NOT_FOUND,
            "{status}"
        );
        status == StatusCode::OK
    }

    fn claim_context(&self, entity: &str, recipients: &[&str]) -> ClaimContext {
        ClaimContext::for_compiled(
            &self.registry,
            entity,
            Some("reader".into()),
            SCOPE,
            Some(PURPOSE.into()),
            vec![],
        )
        .unwrap()
        .with_recipients(recipients.iter().map(|value| (*value).to_owned()).collect())
        .unwrap()
    }

    fn table(&self, entity: &str) -> String {
        format!(
            "registry_data.\"{}\"",
            self.registry.entities()[entity].physical_table
        )
    }
}

struct Decision<'a> {
    subject: &'a str,
    recipient: &'a str,
    purpose: &'a str,
    scope: &'a str,
    decision: &'a str,
    from: time::Duration,
    until: Option<time::Duration>,
}

fn decision<'a>(subject: &'a str, recipient: &'a str, value: &'a str) -> Decision<'a> {
    Decision {
        subject,
        recipient,
        purpose: PURPOSE,
        scope: SCOPE,
        decision: value,
        from: time::Duration::hours(-1),
        until: None,
    }
}

fn at(offset: time::Duration) -> String {
    (OffsetDateTime::now_utc() + offset)
        .replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

fn ids(page: &Value) -> BTreeSet<String> {
    page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("a page carries items: {page}"))
        .iter()
        .map(|item| {
            item["recordIdentifier"]
                .as_str()
                .or_else(|| item["data"]["recordIdentifier"].as_str())
                .unwrap_or_else(|| panic!("an item carries its identifier: {item}"))
                .to_owned()
        })
        .collect()
}

fn hidden_or_empty(status: StatusCode, body: &Value) -> bool {
    status == StatusCode::NOT_FOUND
        || (status == StatusCode::OK && body["items"].as_array().is_some_and(Vec::is_empty))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_consent_gates_every_read_operation_on_id_and_on_reference() {
    let h = Harness::start().await;
    let alice = h.person("Alice").await;
    let bob = h.person("Bob").await;
    let carol = h.person("Carol").await;
    let alice_home = h.create("households", json!({"label": "ALICE-HOME"})).await;
    let bob_home = h.create("households", json!({"label": "BOB-HOME"})).await;
    h.create(
        "household-members",
        json!({"person": alice, "household": alice_home}),
    )
    .await;
    h.create(
        "household-members",
        json!({"person": bob, "household": bob_home}),
    )
    .await;
    let mut enrolments = std::collections::BTreeMap::new();
    for (person, name) in [(&alice, "alice"), (&bob, "bob"), (&carol, "carol")] {
        let enrolment = h
            .create(
                "enrolments",
                json!({"person": person, "programme": format!("meals-{name}")}),
            )
            .await;
        enrolments.insert(person.clone(), enrolment);
    }
    for (person, home) in [(&alice, &alice_home), (&bob, &bob_home)] {
        h.create(
            "enrolment-households",
            json!({"enrolment": enrolments[person], "household": home}),
        )
        .await;
    }
    let wfp = h.reader(WFP_CLIENT, PURPOSE);
    let alpha = h.reader(ALPHA_CLIENT, PURPOSE);

    // No consent row yet: the gated profile sees nothing at all.
    let list = h
        .get(
            &format!("/v1/records/persons?accessProfile={SCOPE}&$count=true"),
            &wfp,
        )
        .await;
    assert_eq!(list["count"], 0, "{list}");

    h.decide(decision(&alice, "wfp", "given")).await;
    h.decide(decision(&carol, "wfp", "given")).await;

    // get, on: id and on: person.
    let body = h
        .get(
            &format!("/v1/records/persons/{alice}?accessProfile={SCOPE}"),
            &wfp,
        )
        .await;
    assert_eq!(body["data"]["domainData"]["givenName"], "Alice", "{body}");
    assert_eq!(
        h.status(
            &format!("/v1/records/persons/{bob}?accessProfile={SCOPE}"),
            &wfp
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.status(
            &format!("/v1/records/persons/{alice}?accessProfile={SCOPE}"),
            &alpha
        )
        .await,
        StatusCode::NOT_FOUND,
        "a give to one organization is not a give to another"
    );
    h.get(
        &format!(
            "/v1/records/enrolments/{}?accessProfile={SCOPE}",
            enrolments[&alice]
        ),
        &wfp,
    )
    .await;
    assert_eq!(
        h.status(
            &format!(
                "/v1/records/enrolments/{}?accessProfile={SCOPE}",
                enrolments[&bob]
            ),
            &wfp
        )
        .await,
        StatusCode::NOT_FOUND
    );

    // list and count, with a continuation cursor taken while both are visible.
    let mut cursors = Vec::new();
    for (route, expected) in [
        ("persons", BTreeSet::from([alice.clone(), carol.clone()])),
        (
            "enrolments",
            BTreeSet::from([enrolments[&alice].clone(), enrolments[&carol].clone()]),
        ),
    ] {
        let page = h
            .get(
                &format!("/v1/records/{route}?accessProfile={SCOPE}&$count=true"),
                &wfp,
            )
            .await;
        assert_eq!(page["count"], 2, "{route}: {page}");
        assert_eq!(ids(&page), expected, "{route}");
        let first = h
            .get(
                &format!("/v1/records/{route}?accessProfile={SCOPE}&$top=1&$count=true"),
                &wfp,
            )
            .await;
        assert_eq!(first["count"], 2, "{first}");
        cursors.push((
            route,
            first["pageInfo"]["nextCursor"].as_str().unwrap().to_owned(),
        ));
    }
    let page = h
        .get(
            &format!("/v1/records/persons?accessProfile={SCOPE}&$count=true"),
            &alpha,
        )
        .await;
    assert_eq!(page["count"], 0, "{page}");

    // lookup, on: id and on: person.
    let lookup_uri = format!("/v1/records/persons:lookup?accessProfile={SCOPE}");
    let lookup = |name: &str| json!({"selector": "given-name", "values": {"givenName": name}});
    let enrolment_lookup_uri = format!("/v1/records/enrolments:lookup?accessProfile={SCOPE}");
    let enrolment_lookup = |name: &str| json!({"selector": "programme", "values": {"programme": format!("meals-{name}")}});
    for (uri, request, expected) in [
        (&lookup_uri, lookup("Alice"), StatusCode::OK),
        (&lookup_uri, lookup("Bob"), StatusCode::NOT_FOUND),
        (
            &enrolment_lookup_uri,
            enrolment_lookup("alice"),
            StatusCode::OK,
        ),
        (
            &enrolment_lookup_uri,
            enrolment_lookup("bob"),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (status, body) = send(&h.app, Method::POST, uri, request.clone(), None, &wfp).await;
        assert_eq!(status, expected, "{uri} {request}: {body}");
    }

    // snapshot (current) and a pinned snapshot over retained history.
    let mut pinned = Vec::new();
    for route in ["persons", "enrolments"] {
        let snapshot = h
            .get(
                &format!("/v1/records/{route}:snapshot?accessProfile={SCOPE}&$count=true"),
                &wfp,
            )
            .await;
        assert_eq!(snapshot["count"], 2, "{route}: {snapshot}");
        pinned.push((route, snapshot["snapshot"].as_str().unwrap().to_owned()));
    }

    // revisions.
    for uri in [
        format!("/v1/records/persons/{alice}/revisions?accessProfile={SCOPE}"),
        format!(
            "/v1/records/enrolments/{}/revisions?accessProfile={SCOPE}",
            enrolments[&alice]
        ),
    ] {
        let revisions = h.get(&uri, &wfp).await;
        assert_eq!(revisions["items"].as_array().unwrap().len(), 1, "{uri}");
    }
    for uri in [
        format!("/v1/records/persons/{bob}/revisions?accessProfile={SCOPE}"),
        format!(
            "/v1/records/enrolments/{}/revisions?accessProfile={SCOPE}",
            enrolments[&bob]
        ),
    ] {
        let (status, body) = send(&h.app, Method::GET, &uri, Value::Null, None, &wfp).await;
        assert!(hidden_or_empty(status, &body), "{uri}: {status} {body}");
    }

    // read path from a gated root, on: id and on: person.
    let path = h
        .get(
            &format!(
                "/v1/records/enrolments/{}/households?accessProfile={SCOPE}",
                enrolments[&alice]
            ),
            &wfp,
        )
        .await;
    assert_eq!(ids(&path), BTreeSet::from([alice_home.clone()]), "{path}");
    let (status, body) = send(
        &h.app,
        Method::GET,
        &format!(
            "/v1/records/enrolments/{}/households?accessProfile={SCOPE}",
            enrolments[&bob]
        ),
        Value::Null,
        None,
        &wfp,
    )
    .await;
    assert!(hidden_or_empty(status, &body), "{status}: {body}");
    assert!(!body.to_string().contains("BOB-HOME"));
    let path = h
        .get(
            &format!("/v1/records/persons/{alice}/households?accessProfile={SCOPE}"),
            &wfp,
        )
        .await;
    assert_eq!(ids(&path), BTreeSet::from([alice_home.clone()]), "{path}");
    let (status, body) = send(
        &h.app,
        Method::GET,
        &format!("/v1/records/persons/{bob}/households?accessProfile={SCOPE}"),
        Value::Null,
        None,
        &wfp,
    )
    .await;
    assert!(hidden_or_empty(status, &body), "{status}: {body}");
    assert!(!body.to_string().contains("BOB-HOME"));

    // Withdraw Alice's consent. The same signed token now reads nothing of
    // Alice on any operation, through any cursor or pinned snapshot.
    h.decide(Decision {
        from: time::Duration::ZERO,
        ..decision(&alice, "wfp", "withdrawn")
    })
    .await;
    for uri in [
        format!("/v1/records/persons/{alice}?accessProfile={SCOPE}"),
        format!(
            "/v1/records/enrolments/{}?accessProfile={SCOPE}",
            enrolments[&alice]
        ),
    ] {
        assert_eq!(h.status(&uri, &wfp).await, StatusCode::NOT_FOUND, "{uri}");
    }
    for (route, expected) in [
        ("persons", carol.clone()),
        ("enrolments", enrolments[&carol].clone()),
    ] {
        let page = h
            .get(
                &format!("/v1/records/{route}?accessProfile={SCOPE}&$count=true"),
                &wfp,
            )
            .await;
        assert_eq!(page["count"], 1, "{route}: {page}");
        assert_eq!(ids(&page), BTreeSet::from([expected.clone()]));
        let snapshot = h
            .get(
                &format!("/v1/records/{route}:snapshot?accessProfile={SCOPE}&$count=true"),
                &wfp,
            )
            .await;
        assert_eq!(snapshot["count"], 1, "{route}: {snapshot}");
        assert_eq!(ids(&snapshot), BTreeSet::from([expected]));
    }
    for (route, cursor) in &cursors {
        let page = h
            .get(
                &format!("/v1/records/{route}?accessProfile={SCOPE}&$skiptoken={cursor}"),
                &wfp,
            )
            .await;
        let seen = ids(&page);
        assert!(!seen.contains(&alice), "{route}: {page}");
        assert!(!seen.contains(&enrolments[&alice]), "{route}: {page}");
    }
    for (route, reference) in &pinned {
        let snapshot = h
            .get(
                &format!(
                    "/v1/records/{route}:snapshot?accessProfile={SCOPE}&snapshot={reference}&$count=true"
                ),
                &wfp,
            )
            .await;
        assert_eq!(
            snapshot["count"], 1,
            "retained history is checked against current consent: {snapshot}"
        );
        let seen = ids(&snapshot);
        assert!(!seen.contains(&alice) && !seen.contains(&enrolments[&alice]));
    }
    for (uri, request) in [
        (&lookup_uri, lookup("Alice")),
        (&enrolment_lookup_uri, enrolment_lookup("alice")),
    ] {
        let (status, body) = send(&h.app, Method::POST, uri, request, None, &wfp).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: {body}");
    }
    for uri in [
        format!("/v1/records/persons/{alice}/revisions?accessProfile={SCOPE}"),
        format!(
            "/v1/records/enrolments/{}/revisions?accessProfile={SCOPE}",
            enrolments[&alice]
        ),
        format!("/v1/records/persons/{alice}/households?accessProfile={SCOPE}"),
        format!(
            "/v1/records/enrolments/{}/households?accessProfile={SCOPE}",
            enrolments[&alice]
        ),
    ] {
        let (status, body) = send(&h.app, Method::GET, &uri, Value::Null, None, &wfp).await;
        assert!(hidden_or_empty(status, &body), "{uri}: {status} {body}");
        assert!(!body.to_string().contains("ALICE-HOME"));
    }
    h.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_consent_orders_decisions_by_capped_time_and_expires_gives() {
    let h = Harness::start().await;
    let wfp = h.reader(WFP_CLIENT, PURPOSE);
    let days = time::Duration::days;

    // A future-dated give is accepted and stays inactive until its `from`.
    let future = h.person("Future").await;
    h.decide(Decision {
        from: time::Duration::seconds(4),
        ..decision(&future, "wfp", "given")
    })
    .await;
    assert!(
        !h.sees(&future, &wfp).await,
        "future-dated give is inactive"
    );

    // A re-give with a backdated `from` is superseded by the withdrawal it
    // predates; a re-give with a current `from` takes effect.
    let regive = h.person("Regive").await;
    h.decide(Decision {
        from: days(-10),
        ..decision(&regive, "wfp", "given")
    })
    .await;
    assert!(h.sees(&regive, &wfp).await);
    h.decide(Decision {
        from: days(-1),
        ..decision(&regive, "wfp", "withdrawn")
    })
    .await;
    assert!(!h.sees(&regive, &wfp).await);
    h.decide(Decision {
        from: days(-5),
        ..decision(&regive, "wfp", "given")
    })
    .await;
    assert!(
        !h.sees(&regive, &wfp).await,
        "a backdated re-give is superseded by the later withdrawal"
    );
    h.decide(Decision {
        from: time::Duration::ZERO,
        ..decision(&regive, "wfp", "given")
    })
    .await;
    assert!(h.sees(&regive, &wfp).await, "a current re-give is in force");

    // Offline ordering: a withdrawal without a prior give is accepted, and a
    // give captured before it but synced after it stays superseded.
    let offline = h.person("Offline").await;
    h.decide(Decision {
        from: time::Duration::hours(-1),
        ..decision(&offline, "wfp", "withdrawn")
    })
    .await;
    h.decide(Decision {
        from: time::Duration::hours(-2),
        ..decision(&offline, "wfp", "given")
    })
    .await;
    assert!(
        !h.sees(&offline, &wfp).await,
        "late-synced give stays superseded"
    );

    // Ties go to the revoke.
    let tie = h.person("Tie").await;
    let instant = time::Duration::hours(-3);
    h.decide(Decision {
        from: instant,
        ..decision(&tie, "wfp", "given")
    })
    .await;
    h.decide(Decision {
        from: instant,
        ..decision(&tie, "wfp", "withdrawn")
    })
    .await;
    assert!(
        !h.sees(&tie, &wfp).await,
        "an equal ordering time supersedes"
    );

    // A future-dated withdrawal is ordered at its creation, so it takes effect
    // now: no caller-supplied time lets a give outrank a later withdrawal.
    let forged = h.person("Forged").await;
    h.decide(decision(&forged, "wfp", "given")).await;
    h.decide(Decision {
        from: days(30),
        ..decision(&forged, "wfp", "withdrawn")
    })
    .await;
    assert!(!h.sees(&forged, &wfp).await);

    // Expiry by maxDuration (P365D from the ordering time) and by `until`.
    let capped = h.person("Capped").await;
    h.decide(Decision {
        from: days(-366),
        ..decision(&capped, "wfp", "given")
    })
    .await;
    assert!(!h.sees(&capped, &wfp).await, "maxDuration expired the give");
    let within = h.person("Within").await;
    h.decide(Decision {
        from: days(-364),
        ..decision(&within, "wfp", "given")
    })
    .await;
    assert!(
        h.sees(&within, &wfp).await,
        "the give is within maxDuration"
    );
    let until = h.person("Until").await;
    h.decide(Decision {
        until: Some(time::Duration::minutes(-1)),
        ..decision(&until, "wfp", "given")
    })
    .await;
    assert!(!h.sees(&until, &wfp).await, "until expired the give");
    let open = h.person("Open").await;
    h.decide(Decision {
        until: Some(time::Duration::hours(1)),
        ..decision(&open, "wfp", "given")
    })
    .await;
    assert!(h.sees(&open, &wfp).await);

    // A refusal also supersedes an earlier give.
    let refused = h.person("Refused").await;
    h.decide(decision(&refused, "wfp", "given")).await;
    h.decide(Decision {
        from: time::Duration::ZERO,
        ..decision(&refused, "wfp", "refused")
    })
    .await;
    assert!(!h.sees(&refused, &wfp).await);

    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        h.sees(&future, &wfp).await,
        "the future-dated give is active once its from has passed"
    );
    h.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_consent_matches_recipient_sets_purpose_and_scope_exactly() {
    let h = Harness::start().await;
    let wfp = h.reader(WFP_CLIENT, PURPOSE);
    let alpha = h.reader(ALPHA_CLIENT, PURPOSE);

    // A give to a group reaches every member organization.
    let grouped = h.person("Grouped").await;
    h.decide(decision(&grouped, "referral-network", "given"))
        .await;
    assert!(h.sees(&grouped, &wfp).await);
    assert!(h.sees(&grouped, &alpha).await);

    // Overlap: withdrawing the organization's own consent leaves the group
    // consent in force; withdrawing the group's ends it for every member.
    let overlap = h.person("Overlap").await;
    h.decide(decision(&overlap, "wfp", "given")).await;
    h.decide(decision(&overlap, "referral-network", "given"))
        .await;
    h.decide(Decision {
        from: time::Duration::ZERO,
        ..decision(&overlap, "wfp", "withdrawn")
    })
    .await;
    assert!(
        h.sees(&overlap, &wfp).await,
        "still visible through the group"
    );
    h.decide(Decision {
        from: time::Duration::ZERO,
        ..decision(&overlap, "referral-network", "withdrawn")
    })
    .await;
    assert!(!h.sees(&overlap, &wfp).await);
    assert!(!h.sees(&overlap, &alpha).await);

    // A give to an organization without clients reaches nobody.
    let beta = h.person("Beta").await;
    h.decide(decision(&beta, "ngo-beta", "given")).await;
    assert!(!h.sees(&beta, &wfp).await);
    assert!(!h.sees(&beta, &alpha).await);

    // Wrong purpose and other scope never match.
    let purpose = h.person("Purpose").await;
    h.decide(Decision {
        purpose: "health-referral",
        ..decision(&purpose, "wfp", "given")
    })
    .await;
    assert!(
        !h.sees(&purpose, &wfp).await,
        "purpose must match the claim"
    );
    let scope = h.person("Scope").await;
    // The retired scope is the only other code the scope vocabulary accepts.
    h.decide(Decision {
        scope: "food-targeting-2025",
        ..decision(&scope, "wfp", "given")
    })
    .await;
    assert!(
        !h.sees(&scope, &wfp).await,
        "scope must be the reading profile"
    );

    // An unmapped client cannot use a gated profile: requesterClients lists
    // only mapped clients, so the request is refused before any read.
    let steward_reader = h.idp.mint_token(json!({
        "aud": AUDIENCE, "registry_actor_kind": "service", "principal": "reader",
        "scope": "records:read", "azp": STEWARD_CLIENT, "purpose": PURPOSE,
    }));
    let status = h
        .status(
            &format!("/v1/records/persons/{grouped}?accessProfile={SCOPE}"),
            &steward_reader,
        )
        .await;
    assert_ne!(status, StatusCode::OK, "unmapped client is refused");
    let status = h
        .status(
            "/v1/records/consent-decisions?accessProfile=recipient-feed",
            &h.feed(STEWARD_CLIENT),
        )
        .await;
    assert_ne!(status, StatusCode::OK, "unmapped client has no feed");

    // At the database, an empty recipient set matches nothing even where the
    // same request with wfp-scope's mapped set (its organization and its
    // group) matches the group give above.
    let persons = h.table("person");
    for (recipients, expected_nonzero) in
        [(&[][..], false), (&["wfp", "referral-network"][..], true)]
    {
        let mut client = h.pool.get_for_test().await.unwrap();
        let transaction = begin_record_transaction(
            &mut client,
            h.lock_key,
            Duration::from_secs(2),
            &h.identity,
            &h.claim_context("person", recipients),
        )
        .await
        .unwrap();
        let visible: i64 = transaction
            .transaction_for_test()
            .query_one(&format!("SELECT count(*) FROM {persons}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(visible > 0, expected_nonzero, "{recipients:?}: {visible}");
        transaction.commit().await.unwrap();
    }

    // The feed shows the caller's gives and withdrawals, group ones
    // included, and never a refusal.
    let refused = h.person("Refused").await;
    let refusal = h.decide(decision(&refused, "wfp", "refused")).await;
    let alpha_only = h.person("AlphaOnly").await;
    let alpha_give = h.decide(decision(&alpha_only, "ngo-alpha", "given")).await;
    let feed = h
        .get(
            "/v1/records/consent-decisions?accessProfile=recipient-feed&$top=100",
            &h.feed(WFP_CLIENT),
        )
        .await;
    let items = feed["items"].as_array().unwrap();
    assert!(!items.is_empty(), "{feed}");
    let mut decisions = BTreeSet::new();
    for item in items {
        let data = if item["domainData"].is_object() {
            &item["domainData"]
        } else {
            &item["data"]["domainData"]
        };
        let recipient = data["recipient"]
            .as_str()
            .unwrap_or_else(|| panic!("a feed item carries its recipient: {item}"));
        assert!(
            recipient == "wfp" || recipient == "referral-network",
            "{item}"
        );
        decisions.insert(
            data["decision"]
                .as_str()
                .unwrap_or_else(|| panic!("a feed item carries its decision: {item}"))
                .to_owned(),
        );
    }
    assert_eq!(
        decisions,
        BTreeSet::from(["given".to_owned(), "withdrawn".to_owned()]),
        "{feed}"
    );
    let feed_ids = ids(&feed);
    assert!(
        !feed_ids.contains(&refusal),
        "a refusal never reaches a recipient"
    );
    assert!(!feed_ids.contains(&alpha_give));
    assert_eq!(
        h.status(
            &format!("/v1/records/consent-decisions/{refusal}?accessProfile=recipient-feed"),
            &h.feed(WFP_CLIENT),
        )
        .await,
        StatusCode::NOT_FOUND
    );
    let alpha_feed = h
        .get(
            "/v1/records/consent-decisions?accessProfile=recipient-feed&$top=100",
            &h.feed(ALPHA_CLIENT),
        )
        .await;
    let alpha_ids = ids(&alpha_feed);
    assert!(alpha_ids.contains(&alpha_give), "{alpha_feed}");
    assert!(alpha_ids.iter().all(|id| id != &refusal));
    h.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_consent_probe_is_blind_and_recipients_parse_strictly() {
    let h = Harness::start().await;
    let wfp = h.reader(WFP_CLIENT, PURPOSE);
    let subject = h.person("Blind").await;
    h.create(
        "enrolments",
        json!({"person": subject, "programme": "meals"}),
    )
    .await;
    h.decide(decision(&subject, "wfp", "given")).await;
    h.decide(Decision {
        from: time::Duration::ZERO,
        ..decision(&subject, "wfp", "withdrawn")
    })
    .await;
    let visible = h.person("Visible").await;
    h.create(
        "enrolments",
        json!({"person": visible, "programme": "meals"}),
    )
    .await;
    h.decide(decision(&visible, "wfp", "given")).await;
    assert!(!h.sees(&subject, &wfp).await);
    assert!(h.sees(&visible, &wfp).await);

    // Running the probe processes consent rows; it must not open them, or the
    // consent source view, to the gated profile's own queries.
    let consent_table = h.table("consent-decision");
    let consent_view = format!(
        "registry_source.\"{}\"",
        h.registry.entities()["consent-decision"]
            .source_relation
            .sql_name
    );
    for entity in ["person", "enrolment"] {
        let mut client = h.pool.get_for_test().await.unwrap();
        let transaction = begin_record_transaction(
            &mut client,
            h.lock_key,
            Duration::from_secs(2),
            &h.identity,
            &h.claim_context(entity, &["wfp"]),
        )
        .await
        .unwrap();
        let sql = transaction.transaction_for_test();
        let rows: i64 = sql
            .query_one(&format!("SELECT count(*) FROM {}", h.table(entity)), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(rows, 1, "{entity}: only the consented subject is visible");
        for relation in [&consent_table, &consent_view] {
            let rows = sql
                .query(&format!("SELECT * FROM {relation}"), &[])
                .await
                .unwrap();
            assert!(
                rows.is_empty(),
                "{entity}: the probe must not disclose consent rows via {relation}"
            );
        }
        let marker: Option<String> = sql
            .query_one(
                "SELECT NULLIF(current_setting('registry.consent_probe', true), '')",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(marker.is_none(), "the probe marker is restored");
        transaction.commit().await.unwrap();
    }

    // A missing or empty recipient set matches nothing; a malformed one
    // raises and fails the request.
    let persons = h.table("person");
    for (value, outcome) in [
        ("", Some(0_i64)),
        ("[]", Some(0)),
        ("[\"ngo-alpha\"]", Some(0)),
        ("[\"wfp\"]", Some(1)),
        ("{}", None),
        ("[1]", None),
        ("\"wfp\"", None),
        ("not json", None),
        ("[\"wfp\", null]", None),
    ] {
        let mut client = h.pool.get_for_test().await.unwrap();
        let transaction = begin_record_transaction(
            &mut client,
            h.lock_key,
            Duration::from_secs(2),
            &h.identity,
            &h.claim_context("person", &["wfp"]),
        )
        .await
        .unwrap();
        let sql = transaction.transaction_for_test();
        sql.execute(
            "SELECT set_config('registry.recipients', $1, true)",
            &[&value],
        )
        .await
        .unwrap();
        let result = sql
            .query_one(&format!("SELECT count(*) FROM {persons}"), &[])
            .await;
        match outcome {
            Some(expected) => {
                let count: i64 = result
                    .unwrap_or_else(|error| panic!("{value}: {error}"))
                    .get(0);
                assert_eq!(count, expected, "{value}");
                transaction.commit().await.unwrap();
            }
            None => {
                assert!(result.is_err(), "{value} must fail closed");
            }
        }
    }

    // Exact catalog verification rejects an altered probe and an extra
    // plausible probe name.
    let (migration, task) = h.database.connect_migration().await;
    let catalog = ExpectedManagedCatalog::compiled(&h.registry);
    let probe = h
        .registry
        .ddl()
        .functions
        .iter()
        .find(|function| function.name.starts_with("consent_"))
        .expect("the gated permissions compile a consent probe");
    let verify = || {
        verify_catalog_identity_for_catalog(
            &migration,
            &h.identity,
            &catalog,
            &h.database.migration_role,
            &h.database.runtime_role,
        )
    };
    verify().await.expect("installed catalog matches");
    migration
        .batch_execute(&format!(
            "ALTER FUNCTION registry_context.\"{}\"() SECURITY DEFINER",
            probe.name
        ))
        .await
        .unwrap();
    assert!(verify().await.is_err());
    migration
        .batch_execute(&format!(
            "ALTER FUNCTION registry_context.\"{}\"() SECURITY INVOKER",
            probe.name
        ))
        .await
        .unwrap();
    verify().await.expect("restored probe matches");
    // A probe keeps the set shape: the per-key shape of a membership probe
    // under a consent name is foreign, and so is a plausible extra probe.
    migration
        .batch_execute(&format!(
            "ALTER FUNCTION registry_context.\"{}\"() STRICT",
            probe.name
        ))
        .await
        .unwrap();
    assert!(verify().await.is_err());
    migration
        .batch_execute(&format!(
            "ALTER FUNCTION registry_context.\"{}\"() CALLED ON NULL INPUT",
            probe.name
        ))
        .await
        .unwrap();
    verify().await.expect("restored probe matches");
    for extra in [
        "CREATE FUNCTION registry_context.consent_aaaaaaaaaaaaaaaaaaaaaaaa(uuid) \
         RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER AS 'SELECT true'",
        "CREATE FUNCTION registry_context.consent_aaaaaaaaaaaaaaaaaaaaaaaa() \
         RETURNS SETOF uuid LANGUAGE sql STABLE SECURITY INVOKER \
         AS 'SELECT NULL::uuid WHERE false'",
    ] {
        migration.batch_execute(extra).await.unwrap();
        assert!(verify().await.is_err(), "{extra}");
        migration
            .batch_execute(
                "DROP FUNCTION registry_context.consent_aaaaaaaaaaaaaaaaaaaaaaaa; \
                 SELECT 1",
            )
            .await
            .unwrap();
        verify().await.expect("the extra probe is gone");
    }
    task.abort();
    h.database.cleanup().await;
}

/// Every `Function Scan` node of a consent probe in an `EXPLAIN (ANALYZE,
/// FORMAT JSON)` plan, as `(function name, actual loops)`.
fn consent_probe_scans(node: &Value, scans: &mut Vec<(String, u64)>) {
    if node["Node Type"] == "Function Scan" {
        if let Some(name) = node["Function Name"]
            .as_str()
            .filter(|name| name.starts_with("consent_"))
        {
            scans.push((
                name.to_owned(),
                node["Actual Loops"].as_u64().expect("analyzed loops"),
            ));
        }
    }
    for child in node["Plans"].as_array().into_iter().flatten() {
        consent_probe_scans(child, scans);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_consent_probe_runs_once_per_list_and_count() {
    let h = Harness::start().await;
    let mut consented = 0;
    for index in 0..6 {
        let subject = h.person(&format!("Planned {index}")).await;
        h.create(
            "enrolments",
            json!({"person": subject, "programme": "meals"}),
        )
        .await;
        if index % 2 == 0 {
            h.decide(decision(&subject, "wfp", "given")).await;
            consented += 1;
        }
    }
    let wfp = h.reader(WFP_CLIENT, PURPOSE);
    let page = h
        .get(
            &format!("/v1/records/persons?accessProfile={SCOPE}&$top=100&$count=true"),
            &wfp,
        )
        .await;
    assert_eq!(page["count"], consented);

    // The probe is uncorrelated, so however many rows the policy tests, the
    // consent table is scanned once per query, for the table and for the
    // source view the runtime reads, gated on the row's own id (person) and
    // through a reference (enrolment).
    for entity in ["person", "enrolment"] {
        let source = format!(
            "registry_source.\"{}\"",
            h.registry.entities()[entity].source_relation.sql_name
        );
        let mut client = h.pool.get_for_test().await.unwrap();
        let transaction = begin_record_transaction(
            &mut client,
            h.lock_key,
            Duration::from_secs(2),
            &h.identity,
            &h.claim_context(entity, &["wfp"]),
        )
        .await
        .unwrap();
        let sql = transaction.transaction_for_test();
        for relation in [h.table(entity), source] {
            for query in [
                format!("SELECT count(*) FROM {relation}"),
                format!("SELECT * FROM {relation} ORDER BY 1 LIMIT 100"),
            ] {
                let plan: Value = sql
                    .query_one(&format!("EXPLAIN (ANALYZE, FORMAT JSON) {query}"), &[])
                    .await
                    .unwrap()
                    .get(0);
                // One probe call per policy that references it; a read-path
                // policy tests its path setting first, so outside that path
                // its probe never runs.
                let mut scans = Vec::new();
                consent_probe_scans(&plan[0]["Plan"], &mut scans);
                let executed = scans.iter().filter(|(_, loops)| *loops > 0).count();
                assert_eq!(executed, 1, "{entity}: {query}: {plan}");
                assert!(
                    scans.iter().all(|(_, loops)| *loops <= 1),
                    "{entity}: {query}: {plan}"
                );
            }
            let rows: i64 = sql
                .query_one(&format!("SELECT count(*) FROM {relation}"), &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(rows, consented, "{entity}: {relation}");
        }
        transaction.commit().await.unwrap();
    }
    h.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_consent_successors_match_fresh_install_when_added_changed_and_removed() {
    use registry_breg::package::{
        change_set_to_applicable_migration_plan, compiled_registry_change_set,
    };
    use registry_breg::postgres::{
        managed_schema_fingerprint, reconcile_compiled_runtime_acl_for_test,
    };
    // Without the household permission every policy of the gated profile
    // depends on its probe, so renaming the profile below leaves nothing the
    // compiler-applicable plan does not drop. Removing a profile that still
    // grants an ordinary permission leaves that policy behind, independently
    // of consent.
    let mut gated = consent_fixture::source();
    gated["accessProfiles"][0]["permissions"]
        .as_array_mut()
        .unwrap()
        .retain(|permission| permission["entity"] != "household");
    let mut base = gated.clone();
    for permission in base["accessProfiles"][0]["permissions"]
        .as_array_mut()
        .unwrap()
    {
        permission.as_object_mut().unwrap().remove("requireConsent");
    }
    // Ungating keeps the scope code: the profile takes a new id and its
    // former id is retired, since codes are append-only.
    let mut removed = gated.clone();
    removed["accessProfiles"][0]["id"] = json!("food-targeting-open");
    for permission in removed["accessProfiles"][0]["permissions"]
        .as_array_mut()
        .unwrap()
    {
        permission.as_object_mut().unwrap().remove("requireConsent");
    }
    removed["retiredConsentScopes"] = json!(["food-targeting-2025", "food-targeting"]);
    let mut changed = gated.clone();
    let record = changed["entities"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entity| entity["id"] == "consent-decision")
        .unwrap();
    record["consentRecord"]["validity"]["maxDuration"] = json!("P30D");
    record["consentRecord"]["decision"]["revokes"] = json!(["refused", "withdrawn"]);
    let mut previous = consent_fixture::compile(&base).unwrap();
    let upgraded = postgres_harness::TestDatabase::create(1).await;
    let (migration, task) = upgraded.connect_migration().await;
    install_compiled_schema(&migration, &previous, &upgraded.runtime_role)
        .await
        .unwrap();
    for (stage, source) in [("added", gated), ("changed", changed), ("removed", removed)] {
        let candidate = consent_fixture::compile(&source).unwrap();
        let changes = compiled_registry_change_set(&previous, &candidate, "prior-consent-package");
        let plan = change_set_to_applicable_migration_plan(&changes).unwrap_or_else(|error| {
            panic!(
                "{stage} consent access change must produce compiler-owned successor DDL: \
                 {error}; changes: {:?}",
                changes.changes
            )
        });
        assert!(
            !plan.statements.is_empty(),
            "{stage} probe change needs successor DDL"
        );
        for statement in &plan.statements {
            migration
                .batch_execute(&statement.sql)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "{stage} compiler successor statement {} must execute: {error}",
                        statement.id
                    )
                });
        }
        reconcile_compiled_runtime_acl_for_test(&migration, &candidate, &upgraded.runtime_role)
            .await
            .expect("successor policies and probe ACL reconcile");
        let catalog = ExpectedManagedCatalog::compiled(&candidate);
        let actual = managed_schema_fingerprint(&migration, &upgraded.runtime_role, &catalog)
            .await
            .unwrap_or_else(|error| panic!("{stage} upgraded exact catalog: {error:?}"));
        let fresh = postgres_harness::TestDatabase::create(1).await;
        let (fresh_migration, fresh_task) = fresh.connect_migration().await;
        install_compiled_schema(&fresh_migration, &candidate, &fresh.runtime_role)
            .await
            .unwrap();
        let expected = managed_schema_fingerprint(&fresh_migration, &fresh.runtime_role, &catalog)
            .await
            .unwrap();
        assert_eq!(
            actual, expected,
            "{stage} successor must have exactly the fresh candidate catalog"
        );
        fresh_task.abort();
        fresh.cleanup().await;
        previous = candidate;
    }
    task.abort();
    upgraded.cleanup().await;
}

struct AlwaysReady;
impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

/// The latency budget of a gated list: one page of 100 with its count, over
/// 100,000 subjects of which 10,000 carry a live consent row. It records the
/// p95 for review and gates nothing; the budget is 250 ms on a laptop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in PostgreSQL performance measurement"]
async fn real_postgres_consent_gated_list_latency_budget() {
    const SUBJECTS: i64 = 100_000;
    const CONSENTED: i64 = 10_000;
    const SAMPLES: usize = 20;
    let h = Harness::start().await;
    let template = h.person("Template").await;
    h.decide(decision(&template, "wfp", "given")).await;

    // Clone the two rows the HTTP path wrote, so every system column keeps the
    // value the runtime itself stores. The superuser session bypasses RLS.
    let person_table = h.table("person");
    let consent_table = h.table("consent-decision");
    let subject_column = &h.registry.entities()["consent-decision"]
        .stored_fields
        .iter()
        .find(|field| field.logical.id == "subject")
        .expect("the consent record declares its subject")
        .physical_name;
    let (admin, admin_task) = h.database.connect_admin().await;
    admin
        .batch_execute(&format!(
            "INSERT INTO {person_table} \
             SELECT (jsonb_populate_record(p, jsonb_build_object('record_id', gen_random_uuid()))).* \
             FROM {person_table} p, generate_series(2, {SUBJECTS}) \
             WHERE p.record_id = '{template}'; \
             INSERT INTO {consent_table} \
             SELECT (jsonb_populate_record(c, jsonb_build_object( \
                 'record_id', gen_random_uuid(), '{subject_column}', s.record_id))).* \
             FROM {consent_table} c, \
                  (SELECT record_id FROM {person_table} \
                   WHERE record_id <> '{template}' ORDER BY record_id LIMIT {CONSENTED} - 1) s; \
             ANALYZE {person_table}; ANALYZE {consent_table};"
        ))
        .await
        .expect("bulk subjects and consent rows seed");
    admin_task.abort();

    let token = h.reader(WFP_CLIENT, PURPOSE);
    let uri = format!("/v1/records/persons?accessProfile={SCOPE}&$top=100&$count=true");
    h.get(&uri, &token).await;
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = std::time::Instant::now();
        let page = h.get(&uri, &token).await;
        samples.push(started.elapsed());
        assert_eq!(page["count"], CONSENTED, "{}", page["count"]);
        assert_eq!(page["items"].as_array().map(Vec::len), Some(100));
    }
    samples.sort();
    let p95 = samples[(SAMPLES * 95).div_ceil(100) - 1];
    eprintln!(
        "gated list of 100 with count over {SUBJECTS} subjects and {CONSENTED} consent rows: \
         p50 {:?}, p95 {p95:?}, max {:?}",
        samples[SAMPLES / 2],
        samples[SAMPLES - 1],
    );
    h.database.cleanup().await;
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Value,
    idempotency_key: Option<&str>,
    token: &str,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"));
    if let Some(key) = idempotency_key {
        request = request.header("idempotency-key", key);
    }
    let request = request
        .body(if body.is_null() {
            Body::empty()
        } else {
            Body::from(serde_json::to_vec(&body).unwrap())
        })
        .unwrap();
    let response = app.clone().call(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}
