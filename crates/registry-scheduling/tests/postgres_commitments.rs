// SPDX-License-Identifier: Apache-2.0

//! Database-backed commitment tests: the six commitments, availability,
//! cursors, the hold-expiry cycle, and the unanchored-supply refusal,
//! exercised through the pinned HTTP surface against a real PostgreSQL
//! deployment.
//!
//! Every test runs in its own schema inside the database named by
//! `SCHEDULING_TEST_DATABASE_URL`, adopted under one scheduling id, seeded
//! with one location, two pools of one member each, and driven through the
//! same router the runtime serves. Without the variable each test skips with
//! a notice: a skipped test binary is not database verification, so the gate
//! that matters runs with the variable set.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use registry_platform_audit::{AuditHashSecret, AuditKeyHasher};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use registry_scheduling::auth::SchedulingAuthenticator;
use registry_scheduling::config::{DatabaseConfig, OidcConfig, OidcJwksSource};
use registry_scheduling::http::{router, HttpState};
use registry_scheduling::service::SchedulingService;
use registry_scheduling::store::PostgresStore;
use registry_scheduling_core::parse_policy_yaml;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const ISSUER: &str = "https://task-token.test";
const AUDIENCE: &str = "urn:registry-scheduling:test";
const CLIENT: &str = "task-agent";
const SECRET: &[u8] = b"01234567890123456789012345678901";
const SCHEDULING_ID: &str = "commitments-test";
const OFFERING: &str = "registry-update-30";
const SECOND_OFFERING: &str = "registry-review-45";

/// One plain booking grid: slots every 30 minutes around the clock, every
/// day, one hour of lead time, a four-hour cancellation cutoff, and a
/// ten-minute hold. The wide opening keeps every query window these tests
/// use, all at least 110 minutes wide, certain to contain a bookable start
/// regardless of when the test runs, and the single member per pool makes
/// every commitment's capacity effect total: a booked or held slot is not
/// availability. The second offering sells a second pool so one fixture can
/// also pin a commitment against a pool the publication never anchored.
const POLICY: &str = r#"apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1
kind: SchedulingPolicyPackage
scheduling: {id: commitments-test, version: 1}
services:
  - {id: registry-update, label: Registry record update}
  - {id: registry-review, label: Registry record review}
holidaySets: [{id: none, revision: 1, because: test, dates: []}]
openings:
  - id: all-day
    location: north-counter
    holidaySet: none
    weekdays: [mon, tue, wed, thu, fri, sat, sun]
    startTime: "00:00"
    endTime: "23:30"
    effectiveFrom: "2026-01-01"
    effectiveUntil: "2035-06-30"
    because: test
offerings:
  - id: registry-update-30
    service: registry-update
    label: 30-minute counter update
    mode: exact-time
    location: north-counter
    because: test
    cancellationCutoffMinutes: 240
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 0
      bufferAfterMinutes: 0
      leadTimeMinutes: 60
      horizonDays: 60
      pool: north-counter
      startIncrementMinutes: 30
      maxRecipients: 1
    requiresCapabilities: []
    prerequisites: []
  - id: registry-review-45
    service: registry-review
    label: 45-minute record review
    mode: exact-time
    location: north-counter
    because: test
    cancellationCutoffMinutes: 240
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 0
      bufferAfterMinutes: 0
      leadTimeMinutes: 60
      horizonDays: 60
      pool: two-counter
      startIncrementMinutes: 30
      maxRecipients: 1
    requiresCapabilities: []
    prerequisites: []
windows: []
holdPolicy: {ttlMinutes: 10, maxPerCaller: 2, because: test}
"#;

struct Fixture {
    http: Router,
    store: PostgresStore,
    revision: u64,
    /// A standing reader: the reads scope, no task grant.
    reader: String,
    /// The booking agent: reads and explain scopes plus the full task grant.
    agent: String,
}

impl Fixture {
    async fn request(
        &self,
        method: &str,
        uri: &str,
        token: &str,
        idempotency: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json");
        if let Some(key) = idempotency {
            builder = builder.header("idempotency-key", key);
        }
        let body = match body {
            Some(value) => Body::from(value.to_string()),
            None => Body::empty(),
        };
        let response = self
            .http
            .clone()
            .oneshot(builder.body(body).expect("a well-formed test request"))
            .await
            .expect("an in-process request always answers");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("a bounded test body");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("a JSON test body")
        };
        (status, value)
    }

    async fn get(&self, uri: &str, token: &str) -> (StatusCode, Value) {
        self.request("GET", uri, token, None, None).await
    }

    async fn post(&self, uri: &str, token: &str, key: &str, body: Value) -> (StatusCode, Value) {
        self.request("POST", uri, token, Some(key), Some(body))
            .await
    }

    async fn delete(&self, uri: &str, token: &str) -> (StatusCode, Value) {
        self.request("DELETE", uri, token, None, None).await
    }
}

/// A fresh deployment in its own schema: migrated, adopted, seeded, published
/// with every pool the policy names, and serving through the same router the
/// runtime serves.
async fn fixture() -> Option<Fixture> {
    let policy = parse_policy_yaml(POLICY).expect("the scheduling test policy");
    let mut pool_ids: Vec<String> = policy
        .offerings
        .iter()
        .filter_map(|offering| offering.exact_time.as_ref().map(|exact| exact.pool.clone()))
        .collect();
    pool_ids.sort();
    pool_ids.dedup();
    fixture_anchoring(&pool_ids).await
}

/// A fresh deployment whose publication anchored exactly `pool_ids`, so a
/// test can pin what happens when a policy names a pool no anchor covers.
async fn fixture_anchoring(pool_ids: &[String]) -> Option<Fixture> {
    let Ok(base) = std::env::var("SCHEDULING_TEST_DATABASE_URL") else {
        return None;
    };
    let schema = format!("scheduling_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");

    // The admin connection creates the isolated schema before anything
    // resolves into it: table creation follows search_path, and the scoped
    // URL every store connection carries points at this schema, so it must
    // exist before the migrations run.
    let (admin, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect the scheduling test database");
    tokio::spawn(async move { connection.await.expect("the scheduling admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("an isolated scheduling schema");
    admin
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .expect("the scheduling test schema");

    let secret_name = format!("SCHEDULING_SCHEMA_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&secret_name, &scoped);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("the scheduling test secret resolver");
    let database = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret_name}"),
        migration_url_ref: format!("secret:env/{secret_name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let migration_store =
        PostgresStore::connect_migration(&database, &secrets).expect("the migration store");
    migration_store
        .migrate()
        .await
        .expect("the scheduling migrations");
    let store = PostgresStore::connect_runtime(&database, &secrets).expect("the runtime store");

    // The admin connection seeds the facts the policy resolves supply
    // against — the path operator tooling owns — and the store adopts the
    // deployment identity, the same provisioning verb `scheduling migrate`
    // runs on a fresh database.
    for statement in [
        "INSERT INTO scheduling_locations(location_id, timezone) VALUES('north-counter','UTC')",
        "INSERT INTO scheduling_pools(pool_id) VALUES('north-counter')",
        "INSERT INTO scheduling_pools(pool_id) VALUES('two-counter')",
        "INSERT INTO scheduling_pool_members(resource_id, pool_id, available) \
         VALUES('station-1','north-counter',true)",
        "INSERT INTO scheduling_pool_members(resource_id, pool_id, available) \
         VALUES('station-2','two-counter',true)",
    ] {
        admin
            .batch_execute(statement)
            .await
            .expect("seed the scheduling facts");
    }
    store
        .adopt(SCHEDULING_ID)
        .await
        .expect("adopt the scheduling deployment");

    let policy = parse_policy_yaml(POLICY).expect("the scheduling test policy");
    let digest = policy.policy_digest();
    let revision = store
        .apply_policy(SCHEDULING_ID, &digest, pool_ids, &[])
        .await
        .expect("publish the scheduling policy");
    let keying = AuditHashSecret::new(vec![0x42; 32]).expect("the test audit hash secret");
    let service = Arc::new(SchedulingService::new(
        store.clone(),
        policy,
        SCHEDULING_ID.to_owned(),
        revision,
        digest,
        AuditKeyHasher::Keyed(keying),
        7,
    ));
    let http = router(HttpState {
        service,
        authenticator: Arc::new(authenticator()),
        store: store.clone(),
    });
    Some(Fixture {
        http,
        store,
        revision: u64::try_from(revision).expect("a bounded policy revision"),
        reader: reader_token(),
        agent: agent_token(),
    })
}

fn authenticator() -> SchedulingAuthenticator {
    let oidc = OidcConfig {
        allowed_clients: vec![CLIENT.to_owned()],
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        jwks_uri: None,
        jwks_source: OidcJwksSource::Discovery,
        scope_claim: "registry_scopes".to_owned(),
        reads_scope: "scheduling-read".to_owned(),
        explain_scope: "scheduling-explain".to_owned(),
    };
    let verifier = TokenVerifierConfig::access_token_profile(
        ISSUER,
        vec![AUDIENCE.to_owned()],
        vec![Algorithm::HS256],
        vec!["at+jwt".to_owned()],
    )
    .with_scope_claim("registry_scopes")
    .with_allowed_clients(vec![CLIENT.to_owned()]);
    let keys = Arc::new(JwksFetcher::new_static(
        serde_json::from_value(json!({"keys": [{
            "kty": "oct",
            "kid": "test",
            "alg": "HS256",
            "use": "sig",
            "k": URL_SAFE_NO_PAD.encode(SECRET),
        }]}))
        .expect("the test signing keys"),
        JwksFetcherConfig::defaults(),
    ));
    SchedulingAuthenticator::new(&oidc, verifier, keys)
}

/// Sign an access token, filling in the claims a real token always carries.
fn token(mut claims: Value) -> String {
    let now = Utc::now().timestamp();
    let object = claims.as_object_mut().unwrap();
    object.entry("iss").or_insert(json!(ISSUER));
    object.entry("aud").or_insert(json!(AUDIENCE));
    object.entry("iat").or_insert(json!(now));
    object.entry("exp").or_insert(json!(now + 300));
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test".to_owned());
    header.typ = Some("at+jwt".to_owned());
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap()
}

fn reader_token() -> String {
    token(json!({
        "sub": "principal-read",
        "azp": CLIENT,
        "registry_scopes": "scheduling-read",
        "registry_actor_kind": "service",
    }))
}

/// The task grant the booking agent carries: every action over the test
/// policy's services and location.
fn grant_claims() -> Value {
    json!({
        "registry_actor_kind": "agent",
        "registry_purpose": "registry-update",
        "registry_grant_id": "grant-1",
        "registry_grant_source_issuer": "https://authority.test",
        "registry_grant_client": CLIENT,
        "registry_grant_resource": AUDIENCE,
        "registry_grant_exp": Utc::now().timestamp() + 600,
        "registry_grant_bounds": {
            "type": "scheduling",
            "permissions": [{
                "service": "registry-update",
                "location": "north-counter",
                "actions": [
                    "hold.create",
                    "hold.release",
                    "appointment.create",
                    "appointment.reschedule",
                    "appointment.cancel",
                ],
            }, {
                "service": "registry-review",
                "location": "north-counter",
                "actions": ["appointment.create"],
            }],
        },
        "registry_approver": "approver-1",
    })
}

fn agent_token() -> String {
    let mut claims = json!({
        "sub": "principal-agent",
        "azp": CLIENT,
        "registry_scopes": "scheduling-read scheduling-explain",
        "registry_actor_kind": "service",
    });
    let object = claims.as_object_mut().unwrap();
    object.extend(
        grant_claims()
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    token(claims)
}

/// A complete admission request for `offering` at `slot`.
fn admission(fx: &Fixture, offering: &str, slot: DateTime<Utc>) -> Value {
    json!({
        "offering": offering,
        "start": stamp(slot),
        "party": {"recipients": 1, "attendees": 1},
        "channel": null,
        "duplicateKey": null,
        "policyRevision": fx.revision,
        "windowRevision": null,
        "capabilities": [],
        "prerequisites": [],
        "rescheduleOf": null,
    })
}

fn stamp(moment: DateTime<Utc>) -> String {
    moment.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn moment(value: &Value, field: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value[field].as_str().expect("an RFC 3339 field"))
        .expect("a parseable RFC 3339 field")
        .with_timezone(&Utc)
}

fn availability_uri(offering: &str, from_minutes: i64, to_minutes: i64) -> String {
    let now = Utc::now();
    format!(
        "/v1/availability?offering={offering}&start={}&end={}",
        stamp(now + TimeDelta::minutes(from_minutes)),
        stamp(now + TimeDelta::minutes(to_minutes)),
    )
}

/// The earliest bookable slot the offering lists in `[now + from, now + to]`.
/// The test policy's grid steps every 30 minutes around the clock, so every
/// window these tests use, all at least 110 minutes wide, always carries one.
async fn first_slot(
    fx: &Fixture,
    offering: &str,
    from_minutes: i64,
    to_minutes: i64,
) -> DateTime<Utc> {
    let (status, page) = fx
        .get(
            &availability_uri(offering, from_minutes, to_minutes),
            &fx.reader,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "availability answers over the window"
    );
    let start = page["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| entry["kind"] == "slot")
        .and_then(|entry| entry["start"].as_str())
        .unwrap_or_else(|| panic!("a bookable slot inside [{from_minutes}, {to_minutes}] minutes"));
    DateTime::parse_from_rfc3339(start)
        .expect("a parseable slot start")
        .with_timezone(&Utc)
}

async fn slot_offered(
    fx: &Fixture,
    offering: &str,
    from_minutes: i64,
    to_minutes: i64,
    slot: DateTime<Utc>,
) -> bool {
    let (_, page) = fx
        .get(
            &availability_uri(offering, from_minutes, to_minutes),
            &fx.reader,
        )
        .await;
    page["items"].as_array().is_some_and(|items| {
        items.iter().any(|entry| {
            entry["kind"] == "slot"
                && DateTime::parse_from_rfc3339(entry["start"].as_str().unwrap_or_default())
                    .is_ok_and(|start| start.with_timezone(&Utc) == slot)
        })
    })
}

/// Book directly on a fresh slot of the default offering and return the
/// appointment.
async fn booked(fx: &Fixture, from_minutes: i64, to_minutes: i64, key: &str) -> (String, u64) {
    let slot = first_slot(fx, OFFERING, from_minutes, to_minutes).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            key,
            json!({"hold": null, "admission": admission(fx, OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "the direct create commits");
    (
        appointment["appointmentId"].as_str().unwrap().to_owned(),
        appointment["revision"].as_u64().unwrap(),
    )
}

#[tokio::test]
async fn a_hold_confirms_into_an_appointment_with_attributable_history() {
    let Some(fx) = fixture().await else {
        eprintln!("skipping: SCHEDULING_TEST_DATABASE_URL is not set");
        return;
    };
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "hold-1",
            admission(&fx, OFFERING, slot),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let hold_id = hold["holdId"].as_str().unwrap().to_owned();
    assert_eq!(hold["offering"], OFFERING);
    assert_eq!(hold["resource"], "station-1");
    assert_eq!(hold["policyRevision"], fx.revision);
    assert_eq!(moment(&hold, "start"), slot);
    let expires_in = moment(&hold, "expiresAt") - Utc::now();
    assert!(
        expires_in >= TimeDelta::minutes(9) && expires_in <= TimeDelta::minutes(11),
        "the hold expires at the authored ten minutes: {expires_in}"
    );

    // A retried create with the same key answers as it first did.
    let (status, replayed) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "hold-1",
            admission(&fx, OFFERING, slot),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(replayed["holdId"], hold_id);

    // The held slot is not availability while the hold stands.
    assert!(!slot_offered(&fx, OFFERING, 90, 200, slot).await);

    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "confirm-1",
            json!({"hold": hold_id, "admission": null}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(appointment["state"], "confirmed");
    assert_eq!(appointment["resource"], "station-1");
    assert_eq!(moment(&appointment, "start"), slot);
    let appointment_id = appointment["appointmentId"].as_str().unwrap().to_owned();

    let (status, history) = fx
        .get(
            &format!("/v1/appointments/{appointment_id}/history"),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = history["items"].as_array().unwrap();
    // Confirming mints the appointment as its own claim: one attributable
    // event, the confirmation itself. The hold's own "held" and "consumed"
    // events stay on the hold's history.
    assert_eq!(items.len(), 1, "a confirmed hold books one appointment");
    assert_eq!(items[0]["kind"], "confirmed");
    assert_eq!(items[0]["revision"], 1);
    assert!(items[0]["eventId"].is_string());
    assert!(items[0]["occurredAt"].is_string());
    assert!(items[0]["actor"].is_string());

    let (status, fetched) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched["appointmentId"], appointment_id);
}

#[tokio::test]
async fn a_direct_create_books_without_a_hold_and_exhausts_capacity() {
    let Some(fx) = fixture().await else {
        eprintln!("skipping: SCHEDULING_TEST_DATABASE_URL is not set");
        return;
    };
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "direct-1",
            json!({"hold": null, "admission": admission(&fx, OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(appointment["state"], "confirmed");
    assert_eq!(moment(&appointment, "start"), slot);

    // One member serves one booking: the same start is no longer offered and
    // a second direct create is a capacity refusal.
    assert!(!slot_offered(&fx, OFFERING, 300, 440, slot).await);
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "direct-2",
            json!({"hold": null, "admission": admission(&fx, OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "capacity.exhausted");
}

#[tokio::test]
async fn a_reschedule_moves_under_the_observed_revision_and_refuses_stale_ones() {
    let Some(fx) = fixture().await else {
        eprintln!("skipping: SCHEDULING_TEST_DATABASE_URL is not set");
        return;
    };
    let from = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "resched-create",
            json!({"hold": null, "admission": admission(&fx, OFFERING, from)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let appointment_id = appointment["appointmentId"].as_str().unwrap().to_owned();
    let observed = appointment["revision"].as_u64().unwrap();

    let other = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "resched-1",
            json!({"observedRevision": observed, "admission": admission(&fx, OFFERING, other)}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(moved["revision"], json!(observed + 1));
    assert_eq!(moment(&moved, "start"), other);
    assert!(
        !slot_offered(&fx, OFFERING, 480, 620, other).await,
        "the new start is committed"
    );
    assert!(
        slot_offered(&fx, OFFERING, 300, 440, from).await,
        "the replaced start is bookable again"
    );

    let (status, problem) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "resched-2",
            json!({"observedRevision": observed, "admission": admission(&fx, OFFERING, other)}),
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(problem["code"], "revision.mismatch");
}

#[tokio::test]
async fn cancellation_respects_the_cutoff_and_replays_its_verdict() {
    let Some(fx) = fixture().await else {
        eprintln!("skipping: SCHEDULING_TEST_DATABASE_URL is not set");
        return;
    };
    // Near: inside the four-hour cutoff. Far: clear of it.
    let (near_id, near_revision) = booked(&fx, 90, 200, "cancel-near").await;
    let (status, refused) = fx
        .post(
            &format!("/v1/appointments/{near_id}/cancel"),
            &fx.agent,
            "cancel-near-key",
            json!({"observedRevision": near_revision, "reason": "caller cancelled"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refused["code"], "cancellation.cutoff-passed");
    // The refused verdict replays under the same key.
    let (status, replayed) = fx
        .post(
            &format!("/v1/appointments/{near_id}/cancel"),
            &fx.agent,
            "cancel-near-key",
            json!({"observedRevision": near_revision, "reason": "caller cancelled"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(replayed["code"], "cancellation.cutoff-passed");
    let (status, untouched) = fx
        .get(&format!("/v1/appointments/{near_id}"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        untouched["state"], "confirmed",
        "a refused cancel changes nothing"
    );

    let (far_id, far_revision) = booked(&fx, 300, 440, "cancel-far").await;
    let far_slot = moment(
        &fx.get(&format!("/v1/appointments/{far_id}"), &fx.agent)
            .await
            .1,
        "start",
    );
    let (status, cancelled) = fx
        .post(
            &format!("/v1/appointments/{far_id}/cancel"),
            &fx.agent,
            "cancel-far-key",
            json!({"observedRevision": far_revision, "reason": "caller cancelled"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cancelled["state"], "cancelled");
    assert!(cancelled["cancelledAt"].is_string());
    assert!(
        slot_offered(&fx, OFFERING, 300, 440, far_slot).await,
        "a cancelled appointment's capacity is bookable again"
    );
    // The cancelled appointment's history walks newest first: the
    // cancellation over the confirmation it cancelled.
    let (status, history) = fx
        .get(&format!("/v1/appointments/{far_id}/history"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = history["items"].as_array().unwrap();
    let kinds: Vec<&str> = items
        .iter()
        .filter_map(|entry| entry["kind"].as_str())
        .collect();
    assert_eq!(kinds, ["cancelled", "confirmed"]);
    let revisions: Vec<u64> = items
        .iter()
        .map(|entry| entry["revision"].as_u64().expect("a bounded revision"))
        .collect();
    assert_eq!(revisions, [2, 1], "history walks newest first");
    let (status, again) = fx
        .post(
            &format!("/v1/appointments/{far_id}/cancel"),
            &fx.agent,
            "cancel-far-key",
            json!({"observedRevision": far_revision, "reason": "caller cancelled"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["state"], "cancelled");
}

#[tokio::test]
async fn a_release_returns_capacity_answers_replay_and_blocks_confirmation() {
    let Some(fx) = fixture().await else {
        eprintln!("skipping: SCHEDULING_TEST_DATABASE_URL is not set");
        return;
    };
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "hold-r",
            admission(&fx, OFFERING, slot),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let hold_id = hold["holdId"].as_str().unwrap().to_owned();
    assert!(!slot_offered(&fx, OFFERING, 300, 440, slot).await);

    let (status, _) = fx.delete(&format!("/v1/holds/{hold_id}"), &fx.agent).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        slot_offered(&fx, OFFERING, 300, 440, slot).await,
        "the release returns capacity"
    );

    // The release carries the hold's own id as its idempotency key: a retried
    // release answers with the same empty 204.
    let (status, _) = fx.delete(&format!("/v1/holds/{hold_id}"), &fx.agent).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A released hold can no longer be confirmed.
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "confirm-r",
            json!({"hold": hold_id, "admission": null}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "hold.released");
}

#[tokio::test]
async fn an_expired_hold_returns_capacity_and_refuses_confirmation() {
    let Some(fx) = fixture().await else {
        eprintln!("skipping: SCHEDULING_TEST_DATABASE_URL is not set");
        return;
    };
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "hold-x",
            admission(&fx, OFFERING, slot),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let hold_id = hold["holdId"].as_str().unwrap().to_owned();
    assert!(!slot_offered(&fx, OFFERING, 90, 200, slot).await);

    // The hold-expiry worker's pass, run past the hold's due moment.
    let expired = fx
        .store
        .expire_due_holds(Utc::now() + TimeDelta::minutes(11), 100)
        .await
        .expect("the hold expiry pass");
    assert_eq!(expired, 1);
    assert!(
        slot_offered(&fx, OFFERING, 90, 200, slot).await,
        "capacity reappears"
    );

    // Once the sweeper has closed the hold, confirmation meets a claim in no
    // longer active state and answers hold.released; the distinct hold.expired
    // refusal belongs to the window between lapse and sweep, which this suite
    // cannot reach without sleeping past the TTL.
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "confirm-x",
            json!({"hold": hold_id, "admission": null}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "hold.released");
}

#[tokio::test]
async fn cursors_page_their_own_listing_and_refuse_foreign_contexts() {
    let Some(fx) = fixture().await else {
        eprintln!("skipping: SCHEDULING_TEST_DATABASE_URL is not set");
        return;
    };
    let (status, first) = fx.get("/v1/services?limit=1", &fx.reader).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    let cursor = first["nextCursor"].as_str().unwrap().to_owned();
    let first_id = first["items"][0]["id"].as_str().unwrap().to_owned();

    let (status, second) = fx
        .get(&format!("/v1/services?limit=1&cursor={cursor}"), &fx.reader)
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = second["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_ne!(items[0]["id"], first_id, "the page after the cursor is new");
    assert!(
        second["nextCursor"].is_null(),
        "two services fit in two pages"
    );

    // A cursor answers only the listing that minted it.
    let (status, problem) = fx
        .get(
            &format!("/v1/offerings?limit=1&cursor={cursor}"),
            &fx.reader,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem["code"], "cursor.invalid");

    // Availability cursors bind to the exact window they paged.
    let (status, window) = fx
        .get(
            &format!("{}&limit=1", availability_uri(OFFERING, 90, 200)),
            &fx.reader,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let availability_cursor = window["nextCursor"].as_str().unwrap().to_owned();
    let (status, problem) = fx
        .get(
            &format!(
                "{}&limit=1&cursor={availability_cursor}",
                availability_uri(OFFERING, 300, 440),
            ),
            &fx.reader,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem["code"], "cursor.invalid");
}

#[tokio::test]
async fn the_edge_refuses_unauthenticated_callers_and_unauthorized_mutations() {
    let Some(fx) = fixture().await else {
        eprintln!("skipping: SCHEDULING_TEST_DATABASE_URL is not set");
        return;
    };
    let slot = first_slot(&fx, OFFERING, 300, 440).await;

    let (status, problem) = fx.request("GET", "/v1/services", "", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(problem["code"], "authentication.refused");

    // The reader holds the reads scope but not the explain scope.
    let (status, problem) = fx
        .get(
            &format!(
                "/v1/availability/explain?offering={OFFERING}&start={}",
                stamp(slot)
            ),
            &fx.reader,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], "profile.not-authorized");

    // Readable availability is not authority to book: the reader carries no
    // task grant.
    let (status, problem) = fx
        .post(
            "/v1/holds",
            &fx.reader,
            "reader-hold",
            admission(&fx, OFFERING, slot),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], "operation.not-authorized");

    // With the explain scope, a free start explains as admitting, and a
    // committed one explains the public code with the detailed one behind it.
    let (status, free) = fx
        .get(
            &format!(
                "/v1/availability/explain?offering={OFFERING}&start={}",
                stamp(slot)
            ),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        free["publicCode"].is_null(),
        "a free start explains as admitting"
    );

    let other = first_slot(&fx, OFFERING, 480, 620).await;
    let _ = booked(&fx, 480, 620, "explain-booked").await;
    let (status, explained) = fx
        .get(
            &format!(
                "/v1/availability/explain?offering={OFFERING}&start={}",
                stamp(other)
            ),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    // A contended start carries the same public and detailed code; the
    // detailed vocabulary exists for refusals the public projection hides
    // behind the same few words.
    assert_eq!(explained["publicCode"], "capacity.exhausted");
    assert_eq!(explained["detailedCode"], "capacity.exhausted");
}

#[tokio::test]
async fn a_commitment_against_an_unanchored_pool_refuses_loudly() {
    // Publish the policy with only one of its two pools anchored: reads
    // still answer, while a commitment that must lock the unanchored pool
    // refuses rather than transacting without the anchor it serializes
    // against, and the refusal leaves no stored attempt behind.
    let Some(fx) = fixture_anchoring(&["north-counter".to_owned()]).await else {
        eprintln!("skipping: SCHEDULING_TEST_DATABASE_URL is not set");
        return;
    };
    let slot = first_slot(&fx, SECOND_OFFERING, 300, 440).await;
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "unanchored-1",
            json!({"hold": null, "admission": admission(&fx, SECOND_OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem["code"], "service.unavailable");

    // Nothing was decided: no attempt was recorded, so a fresh key meets the
    // same refusal.
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "unanchored-2",
            json!({"hold": null, "admission": admission(&fx, SECOND_OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem["code"], "service.unavailable");
}

/// Adoption binds one deployment identity: claiming from empty is the
/// fixture's own provisioning line, the same id again is a no-op, and a
/// different id is refused, so two deployments never share one database
/// silently.
#[tokio::test]
async fn adoption_binds_one_identity_and_refuses_a_second() {
    let Some(fx) = fixture().await else {
        eprintln!("skipping: SCHEDULING_TEST_DATABASE_URL is not set");
        return;
    };
    fx.store
        .adopt(SCHEDULING_ID)
        .await
        .expect("re-adopting the same id is a no-op");
    assert!(matches!(
        fx.store.adopt("another-deployment").await,
        Err(registry_scheduling::store::StoreError::Corrupt)
    ));
    // The refused adopt changed nothing: the deployment still answers under
    // its adopted identity.
    let (status, document) = fx.get("/v1/scheduling", &fx.reader).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(document["schedulingId"], SCHEDULING_ID);
}
