// SPDX-License-Identifier: Apache-2.0

//! Database-backed commitment tests: the six commitments, availability,
//! cursors, the hold-expiry cycle, and the unanchored-supply refusal,
//! exercised through the pinned HTTP surface against a real PostgreSQL
//! deployment.
//!
//! Every test runs in its own schema inside the database named by
//! `SCHEDULING_TEST_DATABASE_URL`, adopted under one scheduling id, seeded
//! with one location, two pools of one member each, and driven through the
//! same router the runtime serves. A test binary that passes because its
//! database URL is absent is not database verification, so the variable is
//! required: without it every test in this file fails on the spot.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, SecondsFormat, TimeDelta, Timelike, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use registry_platform_audit::{
    AuditEnvelope, AuditHashSecret, AuditKeyHasher, AuditProfile, JsonlFileSink,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_hooks::delivery::DeliveryOutcome;
use registry_platform_hooks::{EnvelopeLimits, HookEnvelope, HookHandlerSource};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use registry_scheduling::auth::SchedulingAuthenticator;
use registry_scheduling::config::{DatabaseConfig, OidcConfig, OidcJwksSource};
use registry_scheduling::config::{HookDestinationConfig, ReminderDestinationConfig};
use registry_scheduling::hooks::{ActivatedHooks, HookRuntimeIdentity};
use registry_scheduling::http::{router, HttpState};
use registry_scheduling::runtime::{
    dispatch_due_intents, publish_audit_pass, reminder_transport, AuditPublicationState,
    AuditPublisher,
};
use registry_scheduling::service::SchedulingService;
use registry_scheduling::store::{
    CommitError, CommitOutcome, Commitment, PostgresStore, StoreError, SupplyContext,
};
use registry_scheduling_core::{
    location_closure_intervals, location_open_intervals, parse_policy_yaml, AdmissionRefusal,
    AdmissionRequest, CalendarExceptionRecord, Channel, ExceptionRecordKind, LocationRecord,
    OfferingPolicy, PartyCounts, PoolMember, PublishedWindow, RequiredUnitsPolicy, ResourcePool,
    SchedulingFacts, SchedulingPolicy, WindowSubquota,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUER: &str = "https://task-token.test";
const AUDIENCE: &str = "urn:registry-scheduling:test";
const CLIENT: &str = "task-agent";
const SECRET: &[u8] = b"01234567890123456789012345678901";
const SCHEDULING_ID: &str = "commitments-test";
const OFFERING: &str = "registry-update-30";
const SECOND_OFFERING: &str = "registry-review-45";
/// An offering whose service runs twice its start increment, so consecutive
/// published starts overlap each other. It is the only shape that can move an
/// appointment inside the interval it already holds.
const OVERLAPPING_OFFERING: &str = "registry-update-60";

fn observer_policy() -> String {
    format!(
        "{POLICY}hooks:\n  - id: confirmed-observer\n    phase: after\n    trigger: appointment.confirmed\n    projection: [appointmentId, offering, start, end, revision, policyRevision, state]\n    handler: {{kind: url, destinationId: appointment-events}}\n  - id: rescheduled-observer\n    phase: after\n    trigger: appointment.rescheduled\n    projection: [appointmentId, offering, start, end, revision, policyRevision, state]\n    handler: {{kind: url, destinationId: appointment-events}}\n  - id: cancelled-observer\n    phase: after\n    trigger: appointment.cancelled\n    projection: [appointmentId, revision, state]\n    handler: {{kind: url, destinationId: appointment-events}}\n"
    )
}

/// One plain booking grid: slots every 30 minutes around the clock, every
/// day, one hour of lead time, a four-hour cancellation cutoff, and a
/// ten-minute hold. The wide opening keeps every query window these tests
/// use, all at least 110 minutes wide, certain to contain a bookable start
/// regardless of when the test runs, and the single member per pool makes
/// every commitment's capacity effect total: a booked or held slot is not
/// availability. A third offering serves an hour on the same pool at the same
/// half-hour increment, so its published starts overlap one another. The last
/// offering sells a second pool so one fixture can also pin a commitment
/// against a pool the publication never anchored.
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
    reminders: [{minutesBefore: 60, because: test}]
    requiresCapabilities: []
    prerequisites: []
  - id: registry-update-60
    service: registry-update
    label: 60-minute counter update
    mode: exact-time
    location: north-counter
    because: test
    cancellationCutoffMinutes: 240
    exactTime:
      durationMinutes: 60
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
holdPolicy: {ttlMinutes: 10, maxPerCaller: 2, because: test}
"#;

struct Fixture {
    http: Router,
    store: PostgresStore,
    hooks: ActivatedHooks,
    hook_secret_ref: String,
    schema: String,
    /// A session on the test's own schema, for the facts operator tooling
    /// owns and for the rows a test needs to observe or hold directly.
    admin: tokio_postgres::Client,
    revision: u64,
    /// A standing reader: the reads scope, no task grant.
    reader: String,
    /// The booking agent: reads and explain scopes plus the full task grant.
    agent: String,
}

/// Drive one request through the router. The free function takes the router
/// by value so a test can hold two requests in flight at once.
async fn send(
    http: Router,
    method: String,
    uri: String,
    token: String,
    idempotency: Option<String>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method.as_str())
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
    let response = http
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

impl Fixture {
    async fn request(
        &self,
        method: &str,
        uri: &str,
        token: &str,
        idempotency: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        send(
            self.http.clone(),
            method.to_owned(),
            uri.to_owned(),
            token.to_owned(),
            idempotency.map(str::to_owned),
            body,
        )
        .await
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
async fn fixture() -> Fixture {
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
async fn fixture_anchoring(pool_ids: &[String]) -> Fixture {
    fixture_publishing(POLICY, pool_ids).await
}

/// A fresh deployment publishing `policy_yaml` and anchoring exactly
/// `pool_ids`. Window anchors are owned by the records replacement path.
async fn fixture_publishing(policy_yaml: &str, pool_ids: &[String]) -> Fixture {
    fixture_publishing_with_hook_url(policy_yaml, pool_ids, "http://127.0.0.1:9/scheduling-hooks")
        .await
}

async fn fixture_publishing_with_hook_url(
    policy_yaml: &str,
    pool_ids: &[String],
    hook_url: &str,
) -> Fixture {
    let base = std::env::var("SCHEDULING_TEST_DATABASE_URL")
        .expect("SCHEDULING_TEST_DATABASE_URL names a disposable PostgreSQL test server");
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
    let hook_secret_name =
        format!("SCHEDULING_HOOK_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&secret_name, &scoped);
    std::env::set_var(&hook_secret_name, "0123456789abcdef0123456789abcdef");
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
    // against (the path operator tooling owns), and the store adopts the
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

    let policy = parse_policy_yaml(policy_yaml).expect("the scheduling test policy");
    let digest = policy.policy_digest();
    let revision = store
        .apply_policy(SCHEDULING_ID, &digest, pool_ids, &policy)
        .await
        .expect("publish the scheduling policy");
    let keying = AuditHashSecret::new(vec![0x42; 32]).expect("the test audit hash secret");
    let mut hook_destinations = BTreeMap::new();
    for destination_id in policy.hooks.iter().filter_map(|hook| match &hook.handler {
        HookHandlerSource::Url { destination_id } => Some(destination_id),
        HookHandlerSource::Rhai { .. } | HookHandlerSource::Wasm { .. } => None,
    }) {
        hook_destinations.insert(
            destination_id.clone(),
            HookDestinationConfig {
                url: hook_url.to_owned(),
                hmac_sha256_key_ref: format!("secret:env/{hook_secret_name}"),
                attempt_timeout_milliseconds: 5_000,
                maximum_attempts: 1,
            },
        );
    }
    let hooks = ActivatedHooks::activate(
        &policy.hooks,
        &hook_destinations,
        &secrets,
        HookRuntimeIdentity {
            scheduling_id: SCHEDULING_ID.to_owned(),
            policy_revision: revision,
            policy_digest: digest.clone(),
        },
        schema.clone(),
        Duration::from_secs(7 * 24 * 60 * 60),
    )
    .expect("activate the scheduling test hooks");
    let service = Arc::new(
        SchedulingService::new(
            store.clone(),
            policy,
            SCHEDULING_ID.to_owned(),
            revision,
            digest,
            AuditKeyHasher::Keyed(keying),
            7,
        )
        .with_hooks(hooks.clone()),
    );
    let http = router(HttpState {
        service,
        authenticator: Arc::new(authenticator()),
        store: store.clone(),
    });
    Fixture {
        http,
        store,
        hooks,
        hook_secret_ref: format!("secret:env/{hook_secret_name}"),
        schema,
        admin,
        revision: u64::try_from(revision).expect("a bounded policy revision"),
        reader: reader_token(),
        agent: agent_token(),
    }
}

fn authenticator() -> SchedulingAuthenticator {
    let oidc = OidcConfig {
        allowed_clients: vec![CLIENT.to_owned()],
        assertion_issuers: std::collections::BTreeMap::new(),
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

/// Resolve the owned exact-time supply pieces a direct store commitment can
/// borrow. The HTTP service performs the same resolution before it opens the
/// capacity transaction.
fn exact_supply_parts(
    policy: &SchedulingPolicy,
    facts: &SchedulingFacts,
    offering: &OfferingPolicy,
) -> (
    Vec<PoolMember>,
    Vec<registry_platform_calendar::CalendarInterval>,
    Vec<registry_platform_calendar::CalendarInterval>,
) {
    let exact = offering
        .exact_time
        .as_ref()
        .expect("the test offering is exact-time");
    let members = facts
        .pool(&exact.pool)
        .expect("the seeded pool")
        .members
        .clone();
    let timezone = facts
        .location(&offering.location)
        .expect("the seeded location")
        .timezone
        .clone();
    let exceptions: Vec<_> = facts
        .exceptions
        .iter()
        .filter(|exception| exception.location == offering.location)
        .map(|exception| exception.borrowed())
        .collect();
    let open = location_open_intervals(policy, &offering.location, &timezone, &exceptions)
        .expect("resolve the openings");
    let closures = location_closure_intervals(facts, &offering.location, &timezone)
        .expect("resolve the closures");
    (members, open, closures)
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
    agent_token_for("principal-agent")
}

/// A second booking agent, identical in scope and grant and different only in
/// subject, so what it may see is decided by ownership alone.
fn agent_token_for(subject: &str) -> String {
    let mut claims = json!({
        "sub": subject,
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

fn agent_token_for_service(service: &str) -> String {
    let mut grant = grant_claims();
    grant["registry_grant_bounds"]["permissions"] = json!([{
        "service": service,
        "location": "north-counter",
        "actions": ["appointment.create"],
    }]);
    let mut claims = json!({
        "sub": format!("principal-{service}"),
        "azp": CLIENT,
        "registry_scopes": "scheduling-read",
        "registry_actor_kind": "service",
    });
    claims
        .as_object_mut()
        .expect("the claims are an object")
        .extend(
            grant
                .as_object()
                .expect("the grant claims are an object")
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    token(claims)
}

/// A complete admission request for `offering` at `slot`. The wire shape
/// carries no `rescheduleOf`: the exclusion is the runtime's to supply from
/// inside the reschedule transaction, and a caller who sends one is refused
/// as a malformed request.
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

/// The first published start of `offering` whose next start is published too.
/// Both are inside one opening, so an appointment on the first can move onto
/// the second, and for an offering serving longer than its start increment
/// the two intervals overlap.
async fn first_overlapping_pair(
    fx: &Fixture,
    offering: &str,
    from_minutes: i64,
    to_minutes: i64,
) -> (DateTime<Utc>, DateTime<Utc>) {
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
    let starts: Vec<DateTime<Utc>> = page["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| entry["kind"] == "slot")
        .filter_map(|entry| entry["start"].as_str())
        .filter_map(|start| DateTime::parse_from_rfc3339(start).ok())
        .map(|start| start.with_timezone(&Utc))
        .collect();
    starts
        .iter()
        .find_map(|start| {
            let next = *start + TimeDelta::minutes(30);
            starts.contains(&next).then_some((*start, next))
        })
        .unwrap_or_else(|| {
            panic!("two consecutive bookable starts inside [{from_minutes}, {to_minutes}] minutes")
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

async fn hook_fixture() -> Fixture {
    hook_fixture_at("http://127.0.0.1:9/scheduling-hooks").await
}

async fn hook_fixture_at(hook_url: &str) -> Fixture {
    let policy = observer_policy();
    fixture_publishing_with_hook_url(
        &policy,
        &["north-counter".to_owned(), "two-counter".to_owned()],
        hook_url,
    )
    .await
}

async fn captured_hook_envelopes(
    fx: &Fixture,
) -> Vec<(String, String, String, i64, HookEnvelope, Vec<u8>)> {
    fx.admin
        .query(
            "SELECT event_type, trigger, record_reference, record_revision, payload
               FROM registry_outbox ORDER BY outbox_id",
            &[],
        )
        .await
        .expect("read the captured hook outbox")
        .into_iter()
        .map(|row| {
            let payload = row.get::<_, Vec<u8>>(4);
            let envelope = HookEnvelope::from_canonical_bytes(
                &payload,
                &EnvelopeLimits::tightened_to(16 * 1024),
            )
            .expect("the stored hook envelope is canonical");
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                envelope,
                payload,
            )
        })
        .collect()
}

#[tokio::test]
async fn appointment_hooks_capture_matching_lifecycle_rows_with_bounded_projection() {
    let fx = hook_fixture().await;
    let first = first_slot(&fx, OFFERING, 300, 440).await;
    let mut create = admission(&fx, OFFERING, first);
    create["duplicateKey"] = json!("HOOK_DUPLICATE_CANARY");
    let (status, confirmed) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "hook-confirmed",
            json!({"hold": null, "admission": create}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "confirmation commits");
    let appointment_id = confirmed["appointmentId"]
        .as_str()
        .expect("an appointment id")
        .to_owned();
    let first_revision = confirmed["revision"].as_u64().expect("a revision");

    let second = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, rescheduled) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "hook-rescheduled",
            json!({
                "observedRevision": first_revision,
                "admission": admission(&fx, OFFERING, second),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "reschedule commits");
    let second_revision = rescheduled["revision"].as_u64().expect("a revision");

    let (status, cancelled) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/cancel"),
            &fx.agent,
            "hook-cancelled",
            json!({
                "observedRevision": second_revision,
                "reason": "HOOK_REASON_CANARY",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "cancellation commits");

    let captured = captured_hook_envelopes(&fx).await;
    assert_eq!(captured.len(), 3, "one event per matching lifecycle hook");
    let expected = [
        (
            "confirmed-observer",
            "appointment.confirmed",
            &confirmed,
            json!({
                "appointmentId": appointment_id,
                "offering": OFFERING,
                "start": confirmed["start"],
                "end": confirmed["end"],
                "revision": confirmed["revision"],
                "policyRevision": confirmed["policyRevision"],
                "state": "confirmed",
            }),
        ),
        (
            "rescheduled-observer",
            "appointment.rescheduled",
            &rescheduled,
            json!({
                "appointmentId": appointment_id,
                "offering": OFFERING,
                "start": rescheduled["start"],
                "end": rescheduled["end"],
                "revision": rescheduled["revision"],
                "policyRevision": rescheduled["policyRevision"],
                "state": "confirmed",
            }),
        ),
        (
            "cancelled-observer",
            "appointment.cancelled",
            &cancelled,
            json!({
                "appointmentId": appointment_id,
                "revision": cancelled["revision"],
                "state": "cancelled",
            }),
        ),
    ];

    for ((event_type, trigger, reference, revision, envelope, payload), expected) in
        captured.iter().zip(expected)
    {
        let (expected_type, expected_trigger, response, expected_data) = expected;
        assert_eq!(event_type, expected_type);
        assert_eq!(trigger, expected_trigger);
        assert_eq!(envelope.event_type, expected_type);
        assert_eq!(reference, &format!("/v1/appointments/{appointment_id}"));
        assert_eq!(envelope.subject.record_reference, *reference);
        assert_eq!(envelope.subject.record_revision, *revision);
        assert_eq!(json!(*revision), response["revision"]);
        assert_eq!(envelope.data, expected_data);
        assert_eq!(
            envelope.source,
            format!("urn:registrystack:scheduling:{SCHEDULING_ID}")
        );
        assert!(envelope
            .dataschema
            .starts_with("urn:registrystack:scheduling:hook-data:sha256:"));
        assert_eq!(envelope.causation.root, envelope.id);
        assert_eq!(envelope.causation.parent, None);
        assert_eq!(envelope.causation.hop, 0);

        let spelled = std::str::from_utf8(payload).expect("the envelope is UTF-8 JSON");
        for canary in [
            "HOOK_DUPLICATE_CANARY",
            "HOOK_REASON_CANARY",
            "principal-agent",
            "registry_grant_id",
        ] {
            assert!(!spelled.contains(canary), "payload leaked {canary}");
        }
        for excluded in ["actor", "reason", "duplicateKey", "resource", "channel"] {
            assert!(
                envelope.data.get(excluded).is_none(),
                "projection exposed {excluded}"
            );
        }
    }

    let delivery_count: i64 = fx
        .admin
        .query_one("SELECT count(*) FROM registry_webhook_deliveries", &[])
        .await
        .expect("read captured platform delivery rows")
        .get(0);
    assert_eq!(delivery_count, 3, "every envelope has one delivery row");
}

#[tokio::test]
async fn a_hook_capture_failure_rolls_back_the_whole_appointment_transaction() {
    let fx = hook_fixture().await;
    fx.admin
        .batch_execute(
            "ALTER TABLE registry_outbox
             ADD CONSTRAINT test_refuse_hook_capture
             CHECK (event_type <> 'confirmed-observer')",
        )
        .await
        .expect("install the hook capture failure seam");

    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "hook-rollback",
            json!({"hold": null, "admission": admission(&fx, OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem["code"], "service.unavailable");

    let row = fx
        .admin
        .query_one(
            "SELECT
                 (SELECT count(*) FROM scheduling_claims),
                 (SELECT count(*) FROM scheduling_history),
                 (SELECT count(*) FROM scheduling_attempts),
                 (SELECT count(*) FROM registry_outbox),
                 (SELECT count(*) FROM registry_webhook_deliveries)",
            &[],
        )
        .await
        .expect("read the rolled-back commitment tables");
    let counts = (0..5)
        .map(|index| row.get::<_, i64>(index))
        .collect::<Vec<_>>();
    assert_eq!(counts, vec![0, 0, 0, 0, 0]);
    assert!(
        slot_offered(&fx, OFFERING, 300, 440, slot).await,
        "the failed hook capture did not consume capacity"
    );
}

#[tokio::test]
async fn hook_delivery_sends_the_canonical_event_audits_egress_and_refuses_proposals() {
    let destination = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/scheduling-hooks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(
                    r#"{"answer":"proposal","document":{"operation":"cancel"}}"#,
                    "application/json",
                )
                .set_delay(Duration::from_secs(2)),
        )
        .expect(1)
        .mount(&destination)
        .await;
    let fx = hook_fixture_at(&format!("{}/scheduling-hooks", destination.uri())).await;
    let (appointment_id, revision) = booked(&fx, 300, 440, "hook-delivery").await;
    assert_eq!(revision, 1);
    let captured = captured_hook_envelopes(&fx).await;
    assert_eq!(captured.len(), 1);
    let (_, _, _, _, envelope, payload) = &captured[0];

    let delivery = fx.hooks.delivery_service(fx.store.clone());
    delivery
        .verify_retained_bindings()
        .await
        .expect("the retained destination binding is exact");
    let running = tokio::spawn(async move { delivery.deliver_once().await });

    let mut request_seen = false;
    for _ in 0..100 {
        if destination
            .received_requests()
            .await
            .expect("read received hook requests")
            .len()
            == 1
        {
            request_seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(request_seen, "the hook request reached the receiver");

    // The receiver is still delaying its answer. The attempt audit therefore
    // had to commit before egress, while no terminal audit can exist yet.
    let pre_answer_audit = fx
        .admin
        .query(
            "SELECT audit_record FROM scheduling_audit_outbox
              WHERE audit_record->>'event' = 'scheduling.hook-delivery'
              ORDER BY recorded_seq",
            &[],
        )
        .await
        .expect("read the pre-egress hook audit");
    assert_eq!(pre_answer_audit.len(), 1);
    let attempted = pre_answer_audit[0].get::<_, Value>(0);
    assert_eq!(attempted["phase"], "attempt");
    assert_eq!(attempted["outcome"], "attempt_started");
    assert_eq!(attempted["disposition"], "leased");

    let outcome = running
        .await
        .expect("the hook worker task completes")
        .expect("the hook delivery completes");
    assert_eq!(outcome, DeliveryOutcome::Delivered);

    let requests = destination
        .received_requests()
        .await
        .expect("read the delivered hook request");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(
        request.body, *payload,
        "the stored canonical bytes are sent"
    );
    let header = |name: &str| {
        request
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_else(|| panic!("missing valid {name} header"))
    };
    assert_eq!(header("ce-specversion"), "1.0");
    assert_eq!(header("ce-id"), envelope.id);
    assert_eq!(header("ce-source"), envelope.source);
    assert_eq!(header("ce-type"), "confirmed-observer");
    assert_eq!(header("ce-dataschema"), envelope.dataschema);
    let payload_json: Value = serde_json::from_slice(payload).expect("the canonical envelope JSON");
    assert_eq!(header("ce-time"), payload_json["time"]);
    assert_eq!(header("x-registry-event-generation"), "1");
    assert_eq!(header("x-registry-delivery-attempt"), "1");
    assert!(!header("x-registry-delivery-time").is_empty());
    let idempotency_key = header("idempotency-key");
    assert!(idempotency_key.starts_with("sha256:"));
    assert_eq!(idempotency_key.len(), 71);
    let signature = header("x-registry-signature");
    assert!(signature.starts_with("v1="));
    assert_eq!(signature.len(), 46, "v1 plus one HMAC-SHA-256 tag");

    let state = fx
        .admin
        .query_one(
            "SELECT state, attempt, proposal_disposition, proposal_resulting_revision,
                    proposal_code, proposal_summary
               FROM registry_webhook_delivery_state",
            &[],
        )
        .await
        .expect("read the settled hook delivery");
    assert_eq!(state.get::<_, String>(0), "delivered");
    assert_eq!(state.get::<_, i16>(1), 1);
    assert_eq!(
        state.get::<_, Option<String>>(2).as_deref(),
        Some("refused")
    );
    assert_eq!(state.get::<_, Option<i64>>(3), None);
    assert_eq!(
        state.get::<_, Option<String>>(4).as_deref(),
        Some("scheduling.hook.proposal_unsupported")
    );
    assert_eq!(
        state.get::<_, Option<String>>(5).as_deref(),
        Some("Scheduling appointment observer hooks cannot propose changes")
    );

    let audit = fx
        .admin
        .query(
            "SELECT audit_record FROM scheduling_audit_outbox
              WHERE audit_record->>'event' = 'scheduling.hook-delivery'
              ORDER BY recorded_seq",
            &[],
        )
        .await
        .expect("read the settled hook audit");
    assert_eq!(audit.len(), 2);
    let terminal = audit[1].get::<_, Value>(0);
    assert_eq!(terminal["phase"], "terminal");
    assert_eq!(terminal["outcome"], "delivered");
    assert_eq!(terminal["disposition"], "delivered");

    let (status, unchanged) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(unchanged["state"], "confirmed");
    assert_eq!(unchanged["revision"], 1);
    let history_count: i64 = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_history WHERE claim_id=$1",
            &[&Uuid::parse_str(&appointment_id).expect("an appointment UUID")],
        )
        .await
        .expect("read unchanged appointment history")
        .get(0);
    assert_eq!(
        history_count, 1,
        "the proposal changed no appointment state"
    );
}

#[tokio::test]
async fn hook_delivery_audit_failure_prevents_egress() {
    let destination = MockServer::start().await;
    let fx = hook_fixture_at(&format!("{}/scheduling-hooks", destination.uri())).await;
    let _ = booked(&fx, 300, 440, "hook-audit-failure").await;
    fx.admin
        .batch_execute(
            "ALTER TABLE scheduling_audit_outbox
             ADD CONSTRAINT test_refuse_hook_delivery_audit
             CHECK ((audit_record->>'event') IS DISTINCT FROM 'scheduling.hook-delivery')",
        )
        .await
        .expect("install the delivery audit failure seam");

    let delivery = fx.hooks.delivery_service(fx.store.clone());
    assert!(delivery.deliver_once().await.is_err());
    assert!(
        destination
            .received_requests()
            .await
            .expect("read hook requests")
            .is_empty(),
        "a failed pre-egress audit prevents the send"
    );
    let state = fx
        .admin
        .query_one(
            "SELECT state, attempt FROM registry_webhook_delivery_state",
            &[],
        )
        .await
        .expect("read the rolled-back claim state");
    assert_eq!(state.get::<_, String>(0), "pending");
    assert_eq!(state.get::<_, i16>(1), 0);
}

#[tokio::test]
async fn changed_retained_hook_destination_binding_is_refused() {
    let fx = hook_fixture().await;
    let _ = booked(&fx, 300, 440, "hook-binding-change").await;
    let policy = parse_policy_yaml(&observer_policy()).expect("the scheduling hook policy");
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("the scheduling hook secret resolver");
    let destinations = BTreeMap::from([(
        "appointment-events".to_owned(),
        HookDestinationConfig {
            url: "http://127.0.0.1:9/changed-scheduling-hooks".to_owned(),
            hmac_sha256_key_ref: fx.hook_secret_ref.clone(),
            attempt_timeout_milliseconds: 5_000,
            maximum_attempts: 1,
        },
    )]);
    let changed = ActivatedHooks::activate(
        &policy.hooks,
        &destinations,
        &secrets,
        HookRuntimeIdentity {
            scheduling_id: SCHEDULING_ID.to_owned(),
            policy_revision: i64::try_from(fx.revision).expect("a bounded policy revision"),
            policy_digest: policy.policy_digest(),
        },
        fx.schema.clone(),
        Duration::from_secs(7 * 24 * 60 * 60),
    )
    .expect("activate the deliberately changed destination");

    assert!(
        changed
            .delivery_service(fx.store.clone())
            .verify_retained_bindings()
            .await
            .is_err(),
        "retained work cannot be retargeted under the same logical id"
    );
}

#[tokio::test]
async fn a_hold_confirms_into_an_appointment_with_attributable_history() {
    let fx = hook_fixture().await;
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

    let captured = captured_hook_envelopes(&fx).await;
    assert_eq!(
        captured.len(),
        1,
        "hold confirmation captures one observer event"
    );
    assert_eq!(captured[0].0, "confirmed-observer");
    assert_eq!(captured[0].1, "appointment.confirmed");
    assert_eq!(captured[0].4.data["appointmentId"], appointment_id);
}

#[tokio::test]
async fn a_direct_create_books_without_a_hold_and_exhausts_capacity() {
    let fx = fixture().await;
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
async fn exact_time_commitments_include_buffers_outside_the_opening_range() {
    let buffered = POLICY
        .replacen("endTime: \"23:30\"", "endTime: \"23:59\"", 1)
        .replacen("bufferBeforeMinutes: 0", "bufferBeforeMinutes: 30", 1)
        .replacen("durationMinutes: 60", "durationMinutes: 45", 1);
    let fx = fixture_publishing(
        &buffered,
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;
    let day = (Utc::now() + TimeDelta::days(2)).date_naive();
    let midnight = DateTime::<Utc>::from_naive_utc_and_offset(
        day.and_hms_opt(0, 0, 0).expect("midnight"),
        Utc,
    );
    let earlier = midnight - TimeDelta::hours(1);
    let (status, first) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "buffer-boundary-first",
            json!({
                "hold": null,
                "admission": admission(&fx, OVERLAPPING_OFFERING, earlier),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{first}");

    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "buffer-boundary-second",
            json!({"hold": null, "admission": admission(&fx, OFFERING, midnight)}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{problem}");
    assert_eq!(problem["code"], "capacity.exhausted");
}

#[tokio::test]
async fn duplicate_active_keys_are_scoped_to_the_offering() {
    let keyed = POLICY.replacen(
        "    requiresCapabilities: []",
        "    duplicateActiveKey: subject\n    requiresCapabilities: []",
        2,
    );
    let fx = fixture_publishing(
        &keyed,
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;
    let first = first_slot(&fx, OFFERING, 300, 440).await;
    let second = first_slot(&fx, OVERLAPPING_OFFERING, 480, 620).await;
    let mut first_admission = admission(&fx, OFFERING, first);
    first_admission["duplicateKey"] = json!("subject:shared");
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "duplicate-offering-first",
            json!({"hold": null, "admission": first_admission}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");

    let mut second_admission = admission(&fx, OVERLAPPING_OFFERING, second);
    second_admission["duplicateKey"] = json!("subject:shared");
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "duplicate-offering-second",
            json!({"hold": null, "admission": second_admission}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
}

/// The duplicate guard exists so one party holds one live booking per offering
/// at a time. A booking whose time has passed is not live, and counting it
/// would refuse that party forever: the product publishes no completion
/// transition, and cancellation closes at the cutoff before the appointment
/// even starts, so nothing the party can do would ever release the key.
#[tokio::test]
async fn an_elapsed_booking_no_longer_holds_the_partys_duplicate_key() {
    let keyed = POLICY.replacen(
        "    requiresCapabilities: []",
        "    duplicateActiveKey: subject\n    requiresCapabilities: []",
        2,
    );
    let fx = fixture_publishing(
        &keyed,
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;

    let first = first_slot(&fx, OFFERING, 300, 440).await;
    let mut first_admission = admission(&fx, OFFERING, first);
    first_admission["duplicateKey"] = json!("subject:elapsed");
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "duplicate-elapsed-first",
            json!({"hold": null, "admission": first_admission}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");

    let second = first_slot(&fx, OFFERING, 600, 740).await;
    let mut second_admission = admission(&fx, OFFERING, second);
    second_admission["duplicateKey"] = json!("subject:elapsed");
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "duplicate-elapsed-live",
            json!({"hold": null, "admission": second_admission.clone()}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{problem}");
    assert_eq!(
        problem["code"], "booking.duplicate-active",
        "a live booking holds the key"
    );

    // What the passage of time does to that booking, with no sweeper and no
    // transition the party could have reached.
    fx.admin
        .execute(
            "UPDATE scheduling_claims SET \
             displayed_start = now() - interval '2 hours', \
             displayed_end = now() - interval '1 hour', \
             occupied_start = now() - interval '2 hours', \
             occupied_end = now() - interval '1 hour' \
             WHERE duplicate_key = $1",
            &[&"subject:elapsed"],
        )
        .await
        .expect("the standing booking elapses");

    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "duplicate-elapsed-after",
            json!({"hold": null, "admission": second_admission}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "an elapsed booking no longer holds the key: {appointment}"
    );
}

/// A policy may move an exact-time offering's opening dates while retaining
/// its offering and pool. The standing appointment then falls outside the new
/// opening span, but its offering-scoped duplicate key remains active and must
/// still prevent a second booking.
#[tokio::test]
async fn a_duplicate_active_key_survives_an_opening_shift_on_the_same_pool() {
    let keyed = POLICY.replacen(
        "    requiresCapabilities: []",
        "    duplicateActiveKey: subject\n    requiresCapabilities: []",
        1,
    );
    let mut fx = fixture_publishing(
        &keyed,
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;
    let first = first_slot(&fx, OFFERING, 300, 440).await;
    let mut first_admission = admission(&fx, OFFERING, first);
    first_admission["duplicateKey"] = json!("subject:opening-shift");
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "duplicate-before-opening-shift",
            json!({"hold": null, "admission": first_admission}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");

    let next_date = first
        .date_naive()
        .succ_opt()
        .expect("the next opening date is representable");
    let mut replacement = parse_policy_yaml(&keyed).expect("the replacement policy");
    replacement.scheduling.version += 1;
    replacement.openings[0].effective_from = next_date.format("%Y-%m-%d").to_string();
    let replacement_digest = replacement.policy_digest();
    let revision = fx
        .store
        .apply_policy(
            SCHEDULING_ID,
            &replacement_digest,
            &["north-counter".to_owned(), "two-counter".to_owned()],
            &replacement,
        )
        .await
        .expect("shift the opening while retaining the offering and pool");

    let keying = AuditHashSecret::new(vec![0x42; 32]).expect("the test audit hash secret");
    let service = Arc::new(SchedulingService::new(
        fx.store.clone(),
        replacement,
        SCHEDULING_ID.to_owned(),
        revision,
        replacement_digest,
        AuditKeyHasher::Keyed(keying),
        7,
    ));
    fx.http = router(HttpState {
        service,
        authenticator: Arc::new(authenticator()),
        store: fx.store.clone(),
    });
    fx.revision = u64::try_from(revision).expect("a bounded policy revision");

    let second = DateTime::<Utc>::from_naive_utc_and_offset(
        next_date.and_hms_opt(2, 0, 0).expect("a morning slot"),
        Utc,
    );
    let mut second_admission = admission(&fx, OFFERING, second);
    second_admission["duplicateKey"] = json!("subject:opening-shift");
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "duplicate-after-opening-shift",
            json!({"hold": null, "admission": second_admission}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "booking.duplicate-active");

    let active = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims \
             WHERE offering=$1 AND kind='booking' AND state='active'",
            &[&OFFERING],
        )
        .await
        .expect("count active bookings after the refusal");
    assert_eq!(
        active.get::<_, i64>(0),
        1,
        "the duplicate refusal leaves the first booking as the only active one"
    );
}

#[tokio::test]
async fn a_reschedule_moves_under_the_observed_revision_and_refuses_stale_ones() {
    let fx = fixture().await;
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
async fn a_foreign_actor_does_not_learn_the_current_revision() {
    let fx = fixture().await;
    let (appointment_id, _) = booked(&fx, 300, 440, "owner-revision-create").await;
    let stranger = agent_token_for("principal-stranger");
    let other = first_slot(&fx, OFFERING, 480, 620).await;

    let (status, problem) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &stranger,
            "foreign-reschedule-revision",
            json!({
                "observedRevision": 0,
                "admission": admission(&fx, OFFERING, other),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
    assert_eq!(problem["code"], "operation.not-authorized");

    let (status, problem) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/cancel"),
            &stranger,
            "foreign-cancel-revision",
            json!({"observedRevision": 0, "reason": null}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
    assert_eq!(problem["code"], "operation.not-authorized");
}

#[tokio::test]
async fn a_reschedule_refuses_an_admission_for_another_offering() {
    let fx = fixture().await;
    let from = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "resched-offering-create",
            json!({"hold": null, "admission": admission(&fx, OFFERING, from)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    let appointment_id = appointment["appointmentId"].as_str().unwrap();
    let observed = appointment["revision"].as_u64().unwrap();
    let other = first_slot(&fx, SECOND_OFFERING, 480, 620).await;

    let (status, problem) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "resched-offering-mismatch",
            json!({
                "observedRevision": observed,
                "admission": admission(&fx, SECOND_OFFERING, other),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");
    assert_eq!(problem["code"], "request.unprocessable");
}

/// COR-1. A reschedule must never compete with the appointment it is moving.
/// The runtime supplies the appointment's own allocation as the exclusion
/// from inside the commitment transaction, so a move that overlaps the
/// interval the appointment already holds is admitted rather than answered
/// `capacity.exhausted`.
#[tokio::test]
async fn a_reschedule_moves_inside_the_interval_the_appointment_already_holds() {
    let fx = fixture().await;
    let (from, onto) = first_overlapping_pair(&fx, OVERLAPPING_OFFERING, 300, 900).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "self-overlap-create",
            json!({"hold": null, "admission": admission(&fx, OVERLAPPING_OFFERING, from)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let appointment_id = appointment["appointmentId"].as_str().unwrap().to_owned();
    let observed = appointment["revision"].as_u64().unwrap();

    // The new interval starts inside the one the appointment already holds.
    // The only claim standing in its way is its own.
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "self-overlap-move",
            json!({
                "observedRevision": observed,
                "admission": admission(&fx, OVERLAPPING_OFFERING, onto),
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a reschedule excludes its own allocation: {moved}"
    );
    assert_eq!(moment(&moved, "start"), onto);

    // The degenerate case: a move onto the start the appointment already
    // holds, entirely inside its own occupied interval.
    let (status, again) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "self-overlap-restate",
            json!({
                "observedRevision": observed + 1,
                "admission": admission(&fx, OVERLAPPING_OFFERING, onto),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "a move onto its own start: {again}");
    assert_eq!(moment(&again, "start"), onto);
    assert_eq!(again["revision"], json!(observed + 2));
}

/// BL-1. The exclusion belongs to the runtime, never to the caller. A create
/// path handed a live claim's id is refused at the edge, so no caller can
/// name another party's allocation out of the capacity check.
#[tokio::test]
async fn a_create_cannot_name_a_live_claim_to_leave_out_of_the_capacity_check() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bypass-standing",
            json!({"hold": null, "admission": admission(&fx, OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let standing = appointment["appointmentId"].as_str().unwrap().to_owned();

    let mut named = admission(&fx, OFFERING, slot);
    named["rescheduleOf"] = json!(standing);
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bypass-create",
            json!({"hold": null, "admission": named.clone()}),
        )
        .await;
    // The wire shape no longer declares the field, so a body carrying it is
    // refused as unprocessable by the strict request parsing every create
    // route already answers through.
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the create path refuses a caller-named exclusion: {problem}"
    );
    assert_eq!(problem["code"], "request.unprocessable");

    let (status, problem) = fx.post("/v1/holds", &fx.agent, "bypass-hold", named).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the hold path refuses it too: {problem}"
    );
    assert_eq!(problem["code"], "request.unprocessable");

    // The same second caller without the field meets the standing
    // appointment, which is the whole capacity of this pool.
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bypass-plain",
            json!({"hold": null, "admission": admission(&fx, OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "capacity.exhausted");
    assert!(
        !slot_offered(&fx, OFFERING, 300, 440, slot).await,
        "the slot the standing appointment {standing} holds is not availability"
    );
}

#[tokio::test]
async fn cancellation_respects_the_cutoff_and_replays_its_verdict() {
    let fx = fixture().await;
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
    let fx = fixture().await;
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
    let fx = fixture().await;
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

/// Every closing writer advances the claim's revision, so the history event
/// that closes a claim is distinguishable from the one that opened it. The
/// expiry sweeper closes a hold exactly as release and cancellation do, and
/// must leave the same trace behind it.
#[tokio::test]
async fn hold_expiry_advances_the_claim_revision_like_every_other_close() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "hold-revision",
            admission(&fx, OFFERING, slot),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let hold_id = Uuid::parse_str(hold["holdId"].as_str().unwrap()).expect("a hold UUID");

    let expired = fx
        .store
        .expire_due_holds(Utc::now() + TimeDelta::minutes(11), 100)
        .await
        .expect("the hold expiry pass");
    assert_eq!(expired, 1);

    let history = fx
        .store
        .claim_history(hold_id, None, 10)
        .await
        .expect("the hold history");
    let revision_of = |kind: &str| {
        history
            .iter()
            .find(|event| event["kind"] == kind)
            .and_then(|event| event["revision"].as_i64())
    };
    assert_eq!(revision_of("held"), Some(1));
    assert_eq!(
        revision_of("expired"),
        Some(2),
        "the expiry event carries the revision its own close minted"
    );

    let claim = fx
        .store
        .claim(hold_id)
        .await
        .expect("the claim read")
        .expect("the expired hold row");
    assert_eq!(claim.revision, 2);
}

/// SEC-01 and SEC-11 at their shared transaction boundary. A confirmation may
/// enter while its hold is live and pause before it reaches the supply anchor.
/// Once the hold expires, a later transaction may reclaim and book that
/// capacity. The delayed confirmation must observe expiry after it takes the
/// anchor; transferring under its older request time would leave two active
/// bookings on one member.
#[tokio::test]
async fn a_delayed_confirmation_cannot_transfer_rebooked_capacity_after_expiry() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "expiry-race-hold",
            admission(&fx, OFFERING, slot),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the setup hold commits: {hold}"
    );
    let hold_id =
        Uuid::parse_str(hold["holdId"].as_str().expect("a hold id")).expect("a hold UUID");
    let expires_at = moment(&hold, "expiresAt");
    let confirmation_started_at = expires_at - TimeDelta::seconds(1);
    let after_expiry = expires_at + TimeDelta::seconds(1);
    let hold_actor = fx
        .store
        .claim(hold_id)
        .await
        .expect("read the held claim")
        .expect("the hold stands")
        .actor;

    // Capture the confirmation's request clock and resolved supply while the
    // hold is live, then stop it before the capacity transaction opens. This
    // is the same gap as authentication and supply resolution in the service.
    let delayed_store = fx.store.clone();
    let delayed_revision = fx.revision;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
    let delayed = tokio::spawn(async move {
        let policy = parse_policy_yaml(POLICY).expect("the scheduling test policy");
        let offering = policy.offering(OFFERING).expect("the test offering");
        let (facts, facts_revision) = delayed_store
            .facts()
            .await
            .expect("resolve supply before the stall");
        let (members, open, closures) = exact_supply_parts(&policy, &facts, offering);
        let supply = SupplyContext::ExactTime {
            exact: offering
                .exact_time
                .as_ref()
                .expect("the exact-time offering"),
            members: &members,
            open: &open,
            closures: &closures,
        };
        let commitment = Commitment {
            now: confirmation_started_at,
            policy_revision: i64::try_from(delayed_revision).expect("a bounded revision"),
            facts_revision,
            actor: &hold_actor,
            actor_issuer: ISSUER,
            actor_subject: "principal-agent",
            idempotency_key: "expiry-race-confirm",
            request_hash: "sha256:expiry-race-confirm",
            attempt_expires_at: confirmation_started_at + TimeDelta::days(7),
            grant_exp_unix: None,
            audit_event: Uuid::new_v4(),
            audit_record: operator_audit(),
            hooks: None,
        };
        started_tx
            .send(())
            .expect("the test is waiting for the captured confirmation");
        resume_rx.await.expect("resume the delayed confirmation");
        delayed_store
            .confirm_hold(hold_id, offering, &supply, commitment)
            .await
    });
    started_rx
        .await
        .expect("the confirmation captured its live-hold context");

    // A later request sees the hold as expired and legitimately books the
    // released capacity before the older confirmation reaches its anchor.
    let policy = parse_policy_yaml(POLICY).expect("the scheduling test policy");
    let offering = policy.offering(OFFERING).expect("the test offering");
    let (facts, facts_revision) = fx.store.facts().await.expect("resolve current supply");
    let (members, open, closures) = exact_supply_parts(&policy, &facts, offering);
    let supply = SupplyContext::ExactTime {
        exact: offering
            .exact_time
            .as_ref()
            .expect("the exact-time offering"),
        members: &members,
        open: &open,
        closures: &closures,
    };
    let request: AdmissionRequest =
        serde_json::from_value(admission(&fx, OFFERING, slot)).expect("the admission request");
    let competing = fx
        .store
        .create_appointment(
            offering,
            &supply,
            &request,
            Commitment {
                now: after_expiry,
                policy_revision: i64::try_from(fx.revision).expect("a bounded revision"),
                facts_revision,
                actor: "competing-actor",
                actor_issuer: ISSUER,
                actor_subject: "competing-principal",
                idempotency_key: "expiry-race-booking",
                request_hash: "sha256:expiry-race-booking",
                attempt_expires_at: after_expiry + TimeDelta::days(7),
                grant_exp_unix: None,
                audit_event: Uuid::new_v4(),
                audit_record: operator_audit(),
                hooks: None,
            },
        )
        .await
        .expect("the expired hold releases capacity to the competing booking");
    assert!(matches!(competing, CommitOutcome::Booking(_)));

    // The delayed confirmation now reaches the anchor under a clock after the
    // hold's expiry. It must refuse instead of transferring already-booked
    // capacity under its older request observation.
    fx.store.pin_clock(Arc::new(move || after_expiry));
    resume_tx
        .send(())
        .expect("the delayed confirmation is still waiting");
    let confirmation = delayed.await.expect("the confirmation task answers");
    assert!(
        matches!(
            confirmation,
            Err(CommitError::Refused(AdmissionRefusal::HoldExpired))
        ),
        "the delayed confirmation is refused as expired: {confirmation:?}"
    );

    let counts = fx
        .admin
        .query_one(
            "SELECT \
                 (SELECT count(*) FROM scheduling_claims \
                  WHERE kind='booking' AND state='active' AND displayed_start=$1), \
                 (SELECT state FROM scheduling_claims WHERE claim_id=$2)",
            &[&slot, &hold_id],
        )
        .await
        .expect("read the capacity decision");
    assert_eq!(
        counts.get::<_, i64>(0),
        1,
        "the expired hold never creates a second active booking"
    );
    assert_eq!(
        counts.get::<_, String>(1),
        "active",
        "the refused confirmation rolls back without consuming the hold row"
    );
}

#[tokio::test]
async fn cursors_page_their_own_listing_and_refuse_foreign_contexts() {
    let fx = fixture().await;
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
    let fx = fixture().await;
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
async fn explain_assumes_the_offerings_declared_inputs_are_present() {
    let authored = POLICY.replacen(
        "    prerequisites: []",
        "    prerequisites: [registry-update-permit]",
        1,
    );
    let policy = parse_policy_yaml(&authored).expect("the policy with a required input");
    let mut pool_ids: Vec<String> = policy
        .offerings
        .iter()
        .filter_map(|offering| offering.exact_time.as_ref().map(|exact| exact.pool.clone()))
        .collect();
    pool_ids.sort();
    pool_ids.dedup();
    let fx = fixture_publishing(&authored, &pool_ids).await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;

    let (status, explanation) = fx
        .get(
            &format!(
                "/v1/availability/explain?offering={OFFERING}&start={}",
                stamp(slot)
            ),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{explanation}");
    assert!(
        explanation["publicCode"].is_null(),
        "the synthetic probe satisfies declared inputs: {explanation}"
    );
}

#[tokio::test]
async fn a_commitment_against_an_unanchored_pool_refuses_loudly() {
    // Publish the policy with only one of its two pools anchored: reads
    // still answer, while a commitment that must lock the unanchored pool
    // refuses rather than transacting without the anchor it serializes
    // against, and the refusal leaves no stored attempt behind.
    let fx = fixture_anchoring(&["north-counter".to_owned()]).await;
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

#[tokio::test]
async fn an_arrival_offering_without_its_window_record_is_an_operator_gap() {
    let start = (Utc::now() + TimeDelta::hours(3))
        .with_nanosecond(0)
        .expect("second precision");
    let fx = fixture_publishing(
        &policy_with_window(),
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;

    let (status, unavailable) = fx
        .get(&availability_uri(WINDOW_OFFERING, 60, 300), &fx.reader)
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{unavailable}");
    assert_eq!(unavailable["code"], "service.unavailable");

    let (status, unavailable) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "missing-window-record",
            arrival(&fx, start, None),
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{unavailable}");
    assert_eq!(unavailable["code"], "service.unavailable");
}

/// Adoption binds one deployment identity: claiming from empty is the
/// fixture's own provisioning line, the same id again is a no-op, and a
/// different id is refused, so two deployments never share one database
/// silently.
#[tokio::test]
async fn adoption_binds_one_identity_and_refuses_a_second() {
    let fx = fixture().await;
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

/// An idempotency key answers three ways over its life. The same request
/// replays the first answer verbatim. A different request under the same key
/// is refused as reused. A request retried after the receipt's retention
/// period is refused as expired, because the sweep tombstones the receipt
/// instead of deleting it: a deleted receipt would let the retry execute a
/// second time and book a second appointment.
#[tokio::test]
async fn an_idempotency_key_replays_refuses_a_reuse_and_expires_into_a_refusal() {
    let fx = fixture().await;
    let (first, second) = first_overlapping_pair(&fx, OFFERING, 90, 260).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "idem-1",
            json!({"hold": null, "admission": admission(&fx, OFFERING, first)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let appointment_id = appointment["appointmentId"].as_str().unwrap().to_owned();

    // The same key with the same payload replays the stored answer.
    let (status, replayed) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "idem-1",
            json!({"hold": null, "admission": admission(&fx, OFFERING, first)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(replayed["appointmentId"], appointment_id);

    // The same key with a different payload is a reuse, not a replay.
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "idem-1",
            json!({"hold": null, "admission": admission(&fx, OFFERING, second)}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "idempotency.key-reused");

    // The retention sweep passes over the receipt's period.
    let erased = fx
        .store
        .erase_expired_attempts(Utc::now() + TimeDelta::days(8))
        .await
        .expect("the retention sweep runs");
    assert_eq!(erased, 1, "the sweep covers the one stored receipt");

    // The key is spent, not forgotten: the retry is refused, and no second
    // appointment was booked behind it.
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "idem-1",
            json!({"hold": null, "admission": admission(&fx, OFFERING, first)}),
        )
        .await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(problem["code"], "idempotency.expired");

    // A different payload under the spent key is still a reuse: the erased
    // receipt keeps the request it answered, so a conflict outranks expiry.
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "idem-1",
            json!({"hold": null, "admission": admission(&fx, OFFERING, second)}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "idempotency.key-reused");

    // The original appointment stands untouched.
    let (status, fetched) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched["state"], "confirmed");
    assert_eq!(moment(&fetched, "start"), first);
}

/// Two writers reaching the same idempotency key at once: one commits, and
/// the loser is told the key is already spoken for instead of being told the
/// service is unavailable. The loser's whole transaction rolls back, so the
/// slot it was reaching for stays free.
#[tokio::test]
async fn a_concurrent_writer_of_one_idempotency_key_is_refused_not_failed() {
    let fx = fixture().await;
    let (first, second) = first_overlapping_pair(&fx, OFFERING, 90, 260).await;
    let (status, _) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "race-1",
            json!({"hold": null, "admission": admission(&fx, OFFERING, first)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Another writer under the caller's own identity claims "race-2" and has
    // not committed yet, so the request below reads no stored attempt and
    // only meets the key at the moment it writes its own.
    fx.admin
        .batch_execute(
            "BEGIN; \
             INSERT INTO scheduling_attempts(attempt_id, actor_issuer, actor_subject, scope, \
             idempotency_key, request_hash, state, status_code, receipt, expires_at) \
             SELECT gen_random_uuid(), actor_issuer, actor_subject, scope, 'race-2', \
             'a-different-request', state, status_code, receipt, expires_at \
             FROM scheduling_attempts WHERE idempotency_key = 'race-1'",
        )
        .await
        .expect("hold the idempotency key from another writer");

    let contender = tokio::spawn(send(
        fx.http.clone(),
        "POST".to_owned(),
        "/v1/appointments".to_owned(),
        fx.agent.clone(),
        Some("race-2".to_owned()),
        Some(json!({"hold": null, "admission": admission(&fx, OFFERING, second)})),
    ));
    // The contender runs to the point where it writes its attempt and waits
    // there on the key; releasing the other writer decides the race.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    fx.admin
        .batch_execute("COMMIT")
        .await
        .expect("release the held idempotency key");
    let (status, problem) = contender.await.expect("the contending request answers");
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "idempotency.key-reused");

    // Losing the key decided nothing: the slot the contender reached for is
    // still offered.
    assert!(slot_offered(&fx, OFFERING, 90, 260, second).await);
}

#[tokio::test]
async fn a_concurrent_identical_request_replays_the_winning_receipt() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 90, 260).await;
    let body = json!({"hold": null, "admission": admission(&fx, OFFERING, slot)});
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "race-same-seed",
            body.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");

    fx.admin
        .batch_execute(
            "BEGIN; \
             INSERT INTO scheduling_attempts(attempt_id, actor_issuer, actor_subject, scope, \
             idempotency_key, request_hash, state, status_code, receipt, expires_at) \
             SELECT gen_random_uuid(), actor_issuer, actor_subject, scope, 'race-same', \
             request_hash, state, status_code, receipt, expires_at \
             FROM scheduling_attempts WHERE idempotency_key = 'race-same-seed'",
        )
        .await
        .expect("hold the winning receipt from another writer");

    let contender = tokio::spawn(send(
        fx.http.clone(),
        "POST".to_owned(),
        "/v1/appointments".to_owned(),
        fx.agent.clone(),
        Some("race-same".to_owned()),
        Some(body),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    fx.admin
        .batch_execute("COMMIT")
        .await
        .expect("release the winning receipt");
    let (status, replayed) = contender.await.expect("the contending request answers");
    assert_eq!(status, StatusCode::CREATED, "{replayed}");
    assert_eq!(replayed["appointmentId"], appointment["appointmentId"]);
}

/// A success-side idempotency race differs from the exhausted-capacity race
/// above: the contender still has capacity to admit when it reaches the
/// completed-attempt insert. The winner's uncommitted key is invisible at the
/// initial replay read, then wins the insert conflict. The contender must roll
/// back its tentative claim and replay that receipt.
#[tokio::test]
async fn concurrent_identical_admissible_requests_replay_one_winning_success() {
    let start = (Utc::now() + TimeDelta::hours(3))
        .with_nanosecond(0)
        .expect("second precision");
    let fx = fixture_with_window(start).await;
    let body = arrival(&fx, start, Some("public"));
    let (status, winner) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "same-admissible-seed",
            body.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{winner}");

    // Stage the same completed attempt under the contested key without
    // committing it. The two-unit window still has one unit free, so the
    // contender evaluates successfully and reaches this row conflict.
    fx.admin
        .batch_execute(
            "BEGIN; \
             INSERT INTO scheduling_attempts(attempt_id, actor_issuer, actor_subject, scope, \
             idempotency_key, request_hash, state, status_code, receipt, expires_at) \
             SELECT gen_random_uuid(), actor_issuer, actor_subject, scope, \
             'same-admissible-request', request_hash, state, status_code, receipt, expires_at \
             FROM scheduling_attempts WHERE idempotency_key = 'same-admissible-seed'",
        )
        .await
        .expect("hold the winning success from another writer");

    let contender = tokio::spawn(send(
        fx.http.clone(),
        "POST".to_owned(),
        "/v1/appointments".to_owned(),
        fx.agent.clone(),
        Some("same-admissible-request".to_owned()),
        Some(body),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !contender.is_finished(),
        "the contender waits on the completed-attempt conflict"
    );

    fx.admin
        .batch_execute("COMMIT")
        .await
        .expect("release the winning success");
    let replayed = contender.await.expect("the contender answers");
    assert_eq!(replayed.0, StatusCode::CREATED, "{replayed:?}");
    assert_eq!(
        replayed.1["appointmentId"], winner["appointmentId"],
        "the contender receives the winning receipt"
    );

    let claims = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE offering=$1 AND kind='booking'",
            &[&WINDOW_OFFERING],
        )
        .await
        .expect("count committed window claims");
    assert_eq!(
        claims.get::<_, i64>(0),
        1,
        "the losing transaction rolls back its tentative claim"
    );
}

/// The revision a commitment is admitted under is the one the deployment
/// stores, not the one this process read when it started. Operator tooling
/// and a rolling deploy both move the stored revision under a running
/// process, and a caller holding the older number is told the policy moved
/// rather than having a claim written under a revision that no longer
/// stands.
#[tokio::test]
async fn a_policy_applied_under_a_running_process_refuses_the_older_revision() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "moved-hold",
            admission(&fx, OFFERING, slot),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let hold_id = hold["holdId"].as_str().unwrap().to_owned();

    // Operator tooling publishes a different policy against the same
    // deployment, exactly as `schedulingctl` does beside a running runtime.
    let mut replacement = parse_policy_yaml(POLICY).expect("the replacement policy");
    replacement.scheduling.version += 1;
    let replacement_digest = replacement.policy_digest();
    let moved = fx
        .store
        .apply_policy(
            SCHEDULING_ID,
            &replacement_digest,
            &["north-counter".to_owned(), "two-counter".to_owned()],
            &replacement,
        )
        .await
        .expect("publish a second policy revision");
    assert_eq!(moved, i64::try_from(fx.revision).unwrap() + 1);

    // The hold was admitted under the revision that has now moved, so
    // confirming it is refused rather than booked under a stale policy.
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "moved-confirm",
            json!({"hold": hold_id, "admission": null}),
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(problem["code"], "policy.changed");

    // So is a direct create carrying the revision availability advertised
    // before the policy moved.
    let other = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "moved-create",
            json!({"hold": null, "admission": admission(&fx, OFFERING, other)}),
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(problem["code"], "policy.changed");
}

/// A reminder intent is minted when the appointment commits, and a delivery
/// that failed waits out its back-off. Re-claiming a failing intent on every
/// tick would hammer the destination and burn the attempts ceiling in
/// seconds, so the claim predicate reads the back-off the retry wrote.
#[tokio::test]
async fn a_failing_reminder_intent_waits_out_its_back_off() {
    let fx = fixture().await;
    let (appointment_id, _) = booked(&fx, 90, 200, "reminder-1").await;

    // The commitment's own confirmation is due at once; the authored reminder
    // offset is an hour before a start at least ninety minutes out, so the
    // reminder is not due with it.
    let now_due = fx
        .store
        .claim_due_intents(Utc::now(), 100, TimeDelta::minutes(10))
        .await
        .expect("the delivery sweep runs");
    assert_eq!(
        now_due
            .iter()
            .map(|intent| intent.purpose.as_str())
            .collect::<Vec<_>>(),
        vec!["confirmation"],
        "a reminder ahead of its offset is not due yet"
    );

    let due = Utc::now() + TimeDelta::days(1);
    let claimed: Vec<_> = fx
        .store
        .claim_due_intents(due, 100, TimeDelta::minutes(10))
        .await
        .expect("the delivery sweep runs")
        .into_iter()
        .filter(|intent| intent.purpose == "reminder")
        .collect();
    assert_eq!(
        claimed.len(),
        1,
        "the commitment minted one reminder intent"
    );
    assert_eq!(claimed[0].claim_id.to_string(), appointment_id);
    assert_eq!(claimed[0].attempts, 1);
    assert_eq!(claimed[0].payload["appointmentId"], appointment_id);

    // The send failed, so the intent goes back to pending behind a back-off.
    fx.store
        .retry_intent(
            claimed[0].outbox_id,
            due + TimeDelta::minutes(5),
            8,
            claimed[0].attempts,
        )
        .await
        .expect("the failed delivery is scheduled to retry");

    let early: Vec<_> = fx
        .store
        .claim_due_intents(due + TimeDelta::seconds(2), 100, TimeDelta::minutes(10))
        .await
        .expect("the delivery sweep runs")
        .into_iter()
        .filter(|intent| intent.outbox_id == claimed[0].outbox_id)
        .collect();
    assert!(
        early.is_empty(),
        "an intent inside its back-off is not claimed again"
    );

    let later: Vec<_> = fx
        .store
        .claim_due_intents(due + TimeDelta::minutes(6), 100, TimeDelta::minutes(10))
        .await
        .expect("the delivery sweep runs")
        .into_iter()
        .filter(|intent| intent.outbox_id == claimed[0].outbox_id)
        .collect();
    assert_eq!(later.len(), 1, "the back-off passed, so the intent is due");
    assert_eq!(later[0].attempts, 2, "the second attempt is counted once");
}

/// The environment records the fixture seeds, minus the named resources: the
/// document `schedulingctl records apply` would send to retire a station.
fn records_without(retired: &[&str]) -> SchedulingFacts {
    let member = |resource_id: &str| PoolMember {
        resource_id: resource_id.to_owned(),
        capabilities: Vec::new(),
        available: true,
    };
    SchedulingFacts {
        locations: vec![LocationRecord {
            id: "north-counter".to_owned(),
            timezone: "UTC".to_owned(),
        }],
        pools: vec![
            ResourcePool {
                id: "north-counter".to_owned(),
                members: vec![member("station-1")],
            },
            ResourcePool {
                id: "two-counter".to_owned(),
                members: vec![member("station-2")],
            },
        ]
        .into_iter()
        .map(|pool| ResourcePool {
            members: pool
                .members
                .into_iter()
                .filter(|member| !retired.contains(&member.resource_id.as_str()))
                .collect(),
            ..pool
        })
        .collect(),
        windows: Vec::new(),
        exceptions: Vec::new(),
    }
}

fn operator_audit() -> Value {
    json!({
        "actorKind": "operator",
        "operation": "records.apply",
        "outcome": "allowed",
        "reason": "authorization.allowed",
    })
}

#[tokio::test]
async fn a_records_swap_refuses_to_strand_a_resource_an_active_claim_occupies() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let (status, _) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "records-1",
            json!({"hold": null, "admission": admission(&fx, OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "the direct create commits");

    let refusal = fx
        .store
        .replace_facts(
            SCHEDULING_ID,
            &records_without(&["station-1"]),
            Uuid::new_v4(),
            operator_audit(),
        )
        .await
        .expect_err("a swap that strands a live booking is refused");
    assert!(
        refusal.to_string().contains("station-1"),
        "{refusal} does not name the occupied resource"
    );

    // The refusal rolled the whole swap back, so the records stand as they
    // were and the booking still occupies its slot.
    let (standing, _) = fx.store.facts().await.expect("the records survive");
    assert_eq!(
        standing
            .pool("north-counter")
            .map(|pool| pool.members.len()),
        Some(1),
        "the occupied member is still a member"
    );
    assert!(
        !slot_offered(&fx, OFFERING, 90, 200, slot).await,
        "the booking still consumes its slot"
    );

    // Retiring an idle station is exactly what the command is for.
    fx.store
        .replace_facts(
            SCHEDULING_ID,
            &records_without(&["station-2"]),
            Uuid::new_v4(),
            operator_audit(),
        )
        .await
        .expect("retiring an unoccupied resource commits");
    let (standing, _) = fx.store.facts().await.expect("the records are readable");
    assert_eq!(
        standing.pool("two-counter").map(|pool| pool.members.len()),
        Some(0),
        "the idle member is gone"
    );
}

#[tokio::test]
async fn a_records_swap_refuses_to_move_an_occupied_resource_between_pools() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "records-move-create",
            json!({"hold": null, "admission": admission(&fx, OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");

    let mut moved = records_without(&[]);
    let station = moved.pools[0].members.remove(0);
    moved.pools[1].members.push(station);
    let refusal = fx
        .store
        .replace_facts(SCHEDULING_ID, &moved, Uuid::new_v4(), operator_audit())
        .await
        .expect_err("an occupied resource cannot move to another pool");
    assert!(refusal.to_string().contains("station-1"), "{refusal}");

    let (standing, _) = fx.store.facts().await.expect("the records survive");
    assert!(standing.pool("north-counter").is_some_and(|pool| pool
        .members
        .iter()
        .any(|member| member.resource_id == "station-1")));
}

#[tokio::test]
async fn a_records_swap_waits_for_the_capacity_transaction_holding_the_pool() {
    let fx = fixture().await;
    let mut admin = fx.admin;

    // Stand in for a commitment mid-evaluation: it holds the pool's supply
    // anchor from its snapshot until it commits.
    let holder = admin
        .transaction()
        .await
        .expect("the stand-in capacity transaction opens");
    holder
        .execute(
            "SELECT supply_id FROM scheduling_supply WHERE supply_id='north-counter' FOR UPDATE",
            &[],
        )
        .await
        .expect("the stand-in holds the pool anchor");

    let store = fx.store.clone();
    let swap = tokio::spawn(async move {
        store
            .replace_facts(
                SCHEDULING_ID,
                &records_without(&[]),
                Uuid::new_v4(),
                operator_audit(),
            )
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !swap.is_finished(),
        "the swap runs while a commitment holds the pool it would rewrite"
    );

    holder.commit().await.expect("the stand-in commits");
    swap.await
        .expect("the swap task runs to completion")
        .expect("the swap commits once the pool is free");
}

#[tokio::test]
async fn a_history_cursor_is_re_authorized_against_the_caller_of_the_page() {
    let fx = fixture().await;
    let (appointment_id, revision) = booked(&fx, 90, 200, "cursor-actor-1").await;
    let next = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, _) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "cursor-actor-2",
            json!({
                "observedRevision": revision,
                "admission": admission(&fx, OFFERING, next),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the reschedule commits");

    let (status, page) = fx
        .get(
            &format!("/v1/appointments/{appointment_id}/history?limit=1"),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let cursor = page["nextCursor"]
        .as_str()
        .expect("two history events page in two")
        .to_owned();

    // The cursor carries no actor, so the second page is safe only because
    // the listing re-runs its ownership check against whoever presents it.
    let stranger = agent_token_for("principal-stranger");
    let (status, problem) = fx
        .get(
            &format!("/v1/appointments/{appointment_id}/history?limit=1&cursor={cursor}"),
            &stranger,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a stranger holding the token is still not the owner"
    );
    assert_eq!(problem["code"], "operation.not-authorized");

    // The owner continues the same listing normally.
    let (status, page) = fx
        .get(
            &format!("/v1/appointments/{appointment_id}/history?limit=1&cursor={cursor}"),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
}

/// Write a runtime configuration whose migration database is a port nothing
/// listens on, so `scheduling migrate` fails at the connection and nowhere
/// else.
fn unreachable_deployment(root: &std::path::Path) -> std::path::PathBuf {
    let package = root.join("package");
    std::fs::create_dir_all(&package).expect("a package directory");
    std::fs::write(
        package.join(registry_scheduling_core::AUTHORED_POLICY_FILE),
        POLICY,
    )
    .expect("the authored policy");
    let secret_name = format!("SCHEDULING_CLOSED_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(
        &secret_name,
        "postgres://scheduling:scheduling@127.0.0.1:1/scheduling_runtime",
    );
    let document = json!({
        "apiVersion": registry_scheduling_core::SCHEDULING_RUNTIME_API_VERSION,
        "kind": registry_scheduling_core::SCHEDULING_RUNTIME_KIND,
        "package": {"root": package},
        "listener": {"bind": "127.0.0.1:8199", "tlsTermination": "development-loopback"},
        "secretProviders": {"environment": {}},
        "database": {
            "runtimeUrlRef": format!("secret:env/{secret_name}"),
            "migrationUrlRef": format!("secret:env/{secret_name}"),
            "testOnlyPlaintext": true,
        },
        "authentication": {"oidc": {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "allowedClients": [CLIENT],
        }},
        "audit": {"path": root.join("audit.ndjson"), "hashKeyRef": "secret:env/UNUSED"},
        "destinations": {},
        "retention": {"attemptReceiptDays": 7},
    });
    let operator = root.join("runtime.yaml");
    std::fs::write(
        &operator,
        serde_norway::to_string(&document).expect("a serializable configuration"),
    )
    .expect("the runtime configuration");
    operator
}

#[tokio::test]
async fn a_database_that_refuses_at_startup_names_the_step_and_the_cause() {
    let root = tempfile::tempdir().expect("a temporary deployment root");
    let operator = unreachable_deployment(root.path());
    let failure = registry_scheduling::runtime::migrate_from_path(&operator)
        .await
        .expect_err("an unreachable database fails the migration");
    let message = failure.to_string();
    assert!(
        message.contains("schema migration"),
        "{message} does not name the startup step that failed"
    );
    assert!(
        message.to_ascii_lowercase().contains("connect"),
        "{message} does not name why the database was unusable"
    );
    assert!(
        !message.contains("scheduling:scheduling"),
        "the startup failure repeats the database credentials"
    );
}

/// A booking agent whose grant names another location, so its bounds cover no
/// action on the test policy's offering.
fn agent_token_outside_its_bounds() -> String {
    let mut grant = grant_claims();
    grant["registry_grant_bounds"] = json!({
        "type": "scheduling",
        "permissions": [{
            "service": "registry-update",
            "location": "south-counter",
            "actions": ["hold.create"],
        }],
    });
    let mut claims = json!({
        "sub": "principal-elsewhere",
        "azp": CLIENT,
        "registry_scopes": "scheduling-read",
        "registry_actor_kind": "service",
    });
    let object = claims.as_object_mut().unwrap();
    object.extend(
        grant
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    token(claims)
}

/// The pending journal keyed by the reason each record carries.
async fn audit_by_reason(fx: &Fixture) -> std::collections::BTreeMap<String, Value> {
    fx.store
        .pending_audit(100)
        .await
        .expect("the pending audit journal")
        .into_iter()
        .map(|(_, record)| {
            let reason = record["reason"]
                .as_str()
                .expect("an audit record names its reason")
                .to_owned();
            (reason, record)
        })
        .collect()
}

#[tokio::test]
async fn a_permission_refused_before_the_transaction_writes_its_audit_row() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;

    // A grant that covers another location is authority for nothing here.
    let (status, problem) = fx
        .post(
            "/v1/holds",
            &agent_token_outside_its_bounds(),
            "outside-bounds",
            admission(&fx, OFFERING, slot),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], "operation.not-authorized");

    // Readable availability is not authority to book, and the standing
    // reader carries no task grant at all.
    let (status, problem) = fx
        .post(
            "/v1/holds",
            &fx.reader,
            "no-grant",
            admission(&fx, OFFERING, slot),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], "operation.not-authorized");

    let journal = audit_by_reason(&fx).await;
    assert_eq!(
        journal.keys().cloned().collect::<Vec<_>>(),
        vec![
            "authorization.no-grant".to_owned(),
            "authorization.refused".to_owned()
        ],
        "a permission refused before the transaction leaves no journal trail"
    );

    let bounds_refusal = &journal["authorization.refused"];
    assert_eq!(bounds_refusal["outcome"], "denied");
    assert_eq!(bounds_refusal["actorKind"], "agent");
    assert_eq!(bounds_refusal["operation"], "hold.create");
    assert!(
        bounds_refusal["grantPseudonym"].is_string(),
        "a refusal under a present grant names the grant"
    );
    let grantless_refusal = &journal["authorization.no-grant"];
    assert_eq!(grantless_refusal["outcome"], "denied");
    assert_eq!(grantless_refusal["actorKind"], "service");
    assert_eq!(grantless_refusal["operation"], "hold.create");
    assert!(
        grantless_refusal["grantPseudonym"].is_null(),
        "a refusal carrying no grant names none"
    );
    assert!(
        grantless_refusal["purpose"].is_null(),
        "a refusal carrying no grant records no purpose"
    );
    // The journal carries pseudonyms and the operation, never the caller's
    // raw identity and never the bound that failed.
    for record in journal.values() {
        let rendered = record.to_string();
        for raw in ["principal-elsewhere", "principal-read", "north-counter"] {
            assert!(
                !rendered.contains(raw),
                "the refusal audit record repeats {raw} in the clear"
            );
        }
    }
}

/// Every denied record in the pending journal as an (operation, reason) pair,
/// in the order the journal wrote them.
async fn denied_audit_entries(fx: &Fixture) -> Vec<(String, String)> {
    fx.store
        .pending_audit(100)
        .await
        .expect("the pending audit journal")
        .into_iter()
        .map(|(_, record)| record)
        .filter(|record| record["outcome"] == "denied")
        .map(|record| {
            let field = |name: &str| {
                record[name]
                    .as_str()
                    .unwrap_or_else(|| panic!("an audit record names its {name}"))
                    .to_owned()
            };
            (field("operation"), field("reason"))
        })
        .collect()
}

/// SCHEDULING-SEC-14: a commitment the ledger refuses inside the capacity
/// transaction is as attributable as one it allows. A stale observed revision
/// and a cancellation past its cutoff are each a decision about a named
/// appointment under a grant the service already matched, so each leaves a
/// denied record behind. Without them the journal shows the booking and not
/// the refusals that followed it.
#[tokio::test]
async fn refusals_decided_inside_the_capacity_transaction_write_their_audit_rows() {
    let fx = fixture().await;

    // A stale observed revision, refused after the reschedule moved it on.
    let from = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "audited-create",
            json!({"hold": null, "admission": admission(&fx, OFFERING, from)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let appointment_id = appointment["appointmentId"].as_str().unwrap().to_owned();
    let observed = appointment["revision"].as_u64().unwrap();

    let other = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, _) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "audited-resched-1",
            json!({"observedRevision": observed, "admission": admission(&fx, OFFERING, other)}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, problem) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "audited-resched-2",
            json!({"observedRevision": observed, "admission": admission(&fx, OFFERING, other)}),
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(problem["code"], "revision.mismatch");

    // A cancellation inside the four-hour cutoff, refused by the same ledger.
    let (near_id, near_revision) = booked(&fx, 90, 200, "audited-cancel-near").await;
    let (status, problem) = fx
        .post(
            &format!("/v1/appointments/{near_id}/cancel"),
            &fx.agent,
            "audited-cancel-key",
            json!({"observedRevision": near_revision, "reason": "caller cancelled"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "cancellation.cutoff-passed");

    let denied = denied_audit_entries(&fx).await;
    assert_eq!(
        denied,
        vec![
            (
                "appointment.reschedule".to_owned(),
                "authorization.profile".to_owned()
            ),
            (
                "appointment.cancel".to_owned(),
                "authorization.profile".to_owned()
            ),
        ],
        "a refusal the capacity transaction decides is attributable afterwards"
    );

    // The record attributes the decision without repeating the caller.
    for (_, record) in fx
        .store
        .pending_audit(100)
        .await
        .expect("the pending audit journal")
    {
        assert!(
            !record.to_string().contains("principal-agent"),
            "the audit record repeats the caller's raw identity"
        );
    }
}

/// The most octets the claim ledger stores for a caller-chosen duplicate key.
/// It mirrors the CHECK in migration 0001; the edge refuses the same size
/// first, so a caller who exceeds it is answered rather than told the service
/// is down.
const DUPLICATE_KEY_CEILING_BYTES: usize = 256;

/// Write one claim carrying `duplicate_key` straight into the ledger, so the
/// column's own bound is what decides, not a caller-facing check above it.
async fn claim_keyed(fx: &Fixture, duplicate_key: &str) -> Result<u64, tokio_postgres::Error> {
    fx.admin
        .execute(
            "INSERT INTO scheduling_claims(claim_id, kind, state, offering, supply_id, \
             displayed_start, displayed_end, occupied_start, occupied_end, units, \
             duplicate_key, revision, policy_revision, actor) \
             VALUES($1,'booking','active','registry-update-30','station-1', \
             now(), now(), now(), now(), 1, $2, 1, 1, 'actor-pseudonym')",
            &[&Uuid::new_v4(), &duplicate_key],
        )
        .await
}

#[tokio::test]
async fn the_claim_ledger_bounds_a_caller_chosen_duplicate_key() {
    let fx = fixture().await;
    claim_keyed(&fx, &"k".repeat(DUPLICATE_KEY_CEILING_BYTES))
        .await
        .expect("a duplicate key at the ceiling is stored");
    let refused = claim_keyed(&fx, &"k".repeat(DUPLICATE_KEY_CEILING_BYTES + 1)).await;
    assert!(
        refused.is_err(),
        "the ledger stores a duplicate key of any length the body ceiling allows"
    );
}

#[tokio::test]
async fn an_unknown_offering_and_a_malformed_body_answer_their_own_codes() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let absent = "registry-update-90";

    // An offering the deployed policy does not publish is not a precondition
    // the caller can satisfy by reloading: it does not exist.
    let (status, problem) = fx
        .get(&availability_uri(absent, 300, 440), &fx.reader)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem["code"], "request.not-found");

    let (status, problem) = fx
        .get(
            &format!(
                "/v1/availability/explain?offering={absent}&start={}",
                stamp(slot)
            ),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem["code"], "request.not-found");

    let (status, problem) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "absent-hold",
            admission(&fx, absent, slot),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem["code"], "request.not-found");

    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "absent-appointment",
            json!({"hold": null, "admission": admission(&fx, absent, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem["code"], "request.not-found");

    // A create names exactly one of a hold and an admission. Both, neither,
    // or a hold that is not an identifier are all unreadable requests.
    for body in [
        json!({"hold": Uuid::new_v4().to_string(), "admission": admission(&fx, OFFERING, slot)}),
        json!({"hold": null, "admission": null}),
        json!({"hold": "not-an-identifier", "admission": null}),
    ] {
        let (status, problem) = fx
            .post("/v1/appointments", &fx.agent, "malformed", body)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(problem["code"], "request.invalid");
    }
}

#[tokio::test]
async fn the_intents_nobody_will_deliver_are_readable_by_an_operator() {
    let fx = fixture().await;
    let (appointment_id, _) = booked(&fx, 90, 200, "held-1").await;
    let due = Utc::now() + TimeDelta::days(1);
    let claimed = fx
        .store
        .claim_due_intents(due, 100, TimeDelta::minutes(10))
        .await
        .expect("the delivery sweep runs");
    let intent = |purpose: &str| {
        claimed
            .iter()
            .find(|intent| intent.purpose == purpose)
            .expect("the commitment minted this intent")
            .outbox_id
    };

    // One deployment declares no destination, so its reminder stays recorded
    // rather than pretending a delivery happened. One send exhausted its
    // attempts. One was delivered, and one is still inside its back-off.
    fx.store
        .hold_intent_local(intent("reminder"), 1)
        .await
        .expect("the reminder is held locally");
    fx.store
        .retry_intent(intent("confirmation"), due, 0, 1)
        .await
        .expect("the confirmation exhausts its attempts");

    let held = fx
        .store
        .undelivered_intents(100)
        .await
        .expect("the operator reads the undelivered intents");
    let mut seen: Vec<(String, String)> = held
        .iter()
        .map(|intent| (intent.purpose.clone(), intent.delivery_state.clone()))
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        vec![
            ("confirmation".to_owned(), "failed".to_owned()),
            ("reminder".to_owned(), "local".to_owned()),
        ],
        "an intent nothing will deliver is invisible to the operator"
    );

    let reminder = held
        .iter()
        .find(|intent| intent.purpose == "reminder")
        .expect("the held reminder is listed");
    assert_eq!(reminder.claim_id.to_string(), appointment_id);
    assert_eq!(reminder.attempts, 1);
    assert_eq!(reminder.payload["appointmentId"], appointment_id);

    // A delivered intent needs no operator, and neither does one still
    // waiting out its back-off.
    let (second, _) = booked(&fx, 210, 320, "held-2").await;
    let pending = fx
        .store
        .claim_due_intents(Utc::now(), 100, TimeDelta::minutes(10))
        .await
        .expect("the delivery sweep runs");
    let delivered = pending
        .iter()
        .find(|intent| intent.claim_id.to_string() == second)
        .expect("the second commitment confirms at once")
        .outbox_id;
    fx.store
        .mark_intent_delivered(delivered, 1)
        .await
        .expect("the confirmation is delivered");
    let held = fx
        .store
        .undelivered_intents(100)
        .await
        .expect("the operator reads the undelivered intents");
    assert!(
        held.iter().all(|intent| intent.outbox_id != delivered),
        "a delivered intent is listed as needing an operator"
    );
    assert_eq!(
        held.len(),
        2,
        "an intent the sweep will still retry needs no operator"
    );
}

/// AT-01 run in parallel: two callers reach for the same last unit at the same
/// moment. Every commitment locks its supply anchor before it reads the
/// ledger, so the two transactions serialize there and the one that arrives
/// second reads a snapshot already carrying the first booking. Exactly one
/// caller is created, the other is refused a conflict over capacity rather
/// than answered an infrastructure failure for having lost, and each key
/// stays spent on the answer it got: a replay repeats the verdict instead of
/// reaching for the unit a second time.
#[tokio::test]
async fn two_callers_reaching_for_one_unit_book_it_exactly_once() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let contender = agent_token_for("principal-contender");
    let body = json!({"hold": null, "admission": admission(&fx, OFFERING, slot)});

    let first = tokio::spawn(send(
        fx.http.clone(),
        "POST".to_owned(),
        "/v1/appointments".to_owned(),
        fx.agent.clone(),
        Some("last-unit-first".to_owned()),
        Some(body.clone()),
    ));
    let second = tokio::spawn(send(
        fx.http.clone(),
        "POST".to_owned(),
        "/v1/appointments".to_owned(),
        contender.clone(),
        Some("last-unit-second".to_owned()),
        Some(body.clone()),
    ));
    let answers = [
        first.await.expect("the first request answers"),
        second.await.expect("the second request answers"),
    ];

    let created: Vec<&Value> = answers
        .iter()
        .filter(|(status, _)| *status == StatusCode::CREATED)
        .map(|(_, answer)| answer)
        .collect();
    let refused: Vec<&Value> = answers
        .iter()
        .filter(|(status, _)| *status == StatusCode::CONFLICT)
        .map(|(_, answer)| answer)
        .collect();
    assert_eq!(
        created.len(),
        1,
        "exactly one caller books the last unit: {answers:?}"
    );
    assert_eq!(
        refused.len(),
        1,
        "the caller that lost is refused a conflict: {answers:?}"
    );
    assert_eq!(refused[0]["code"], "capacity.exhausted");

    // The ledger carries one claim on the contested slot, the winning
    // appointment is that claim, and availability stops offering the start.
    let active: i64 = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE state='active' AND displayed_start=$1",
            &[&slot],
        )
        .await
        .expect("count the claims on the contested slot")
        .get(0);
    assert_eq!(active, 1, "the request that lost wrote no claim");
    let booked = Uuid::parse_str(
        created[0]["appointmentId"]
            .as_str()
            .expect("an appointment id"),
    )
    .expect("a parseable appointment identifier");
    assert!(
        fx.store
            .claim(booked)
            .await
            .expect("read the booked claim")
            .is_some(),
        "the appointment the winner was answered is in the ledger"
    );
    assert!(!slot_offered(&fx, OFFERING, 90, 200, slot).await);

    // Each caller's key is spent on its own verdict, so neither replay moves
    // the ledger.
    let (replayed, _) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "last-unit-first",
            body.clone(),
        )
        .await;
    assert_eq!(replayed, answers[0].0, "the first key replays its answer");
    let (replayed, _) = fx
        .post("/v1/appointments", &contender, "last-unit-second", body)
        .await;
    assert_eq!(replayed, answers[1].0, "the second key replays its answer");
    let active: i64 = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE state='active' AND displayed_start=$1",
            &[&slot],
        )
        .await
        .expect("count the claims on the contested slot")
        .get(0);
    assert_eq!(active, 1, "replaying either key books nothing further");
}

/// A booking agent whose grant covers holds on both of the test policy's
/// services, so one caller can reach for two pools at once. The default agent
/// may only hold against `registry-update`, and the hold ceiling is a property
/// of the caller, not of the pool a hold happens to land on.
fn agent_token_holding_both_services() -> String {
    let mut grant = grant_claims();
    grant["registry_grant_bounds"]["permissions"][1]["actions"] =
        json!(["hold.create", "hold.release", "appointment.create"]);
    let mut claims = json!({
        "sub": "principal-two-pools",
        "azp": CLIENT,
        "registry_scopes": "scheduling-read scheduling-explain",
        "registry_actor_kind": "service",
    });
    let object = claims.as_object_mut().unwrap();
    object.extend(
        grant
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    token(claims)
}

/// The count of holds one caller currently holds open.
async fn active_holds(fx: &Fixture) -> i64 {
    fx.admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims \
             WHERE kind='hold' AND state='active' AND hold_expires_at > now()",
            &[],
        )
        .await
        .expect("count the caller's open holds")
        .get(0)
}

/// The hold ceiling bounds the caller, not the pool. A commitment locks the
/// supply anchor it is about to draw from, and two holds on two pools lock two
/// different rows, so the ceiling check alone is a count with nothing standing
/// behind it: two concurrent holds each read the same under-ceiling count and
/// both write. The caller-scoped lock is what makes the count mean something,
/// and this test is what says so.
#[tokio::test]
async fn one_caller_cannot_outrun_the_hold_ceiling_across_two_pools() {
    let fx = fixture().await;
    let caller = agent_token_holding_both_services();
    let north = first_slot(&fx, OFFERING, 90, 200).await;
    let (status, _) = fx
        .post(
            "/v1/holds",
            &caller,
            "ceiling-first",
            admission(&fx, OFFERING, north),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "one hold is under the ceiling");

    // Two more at once, against two pools whose supply anchors are distinct
    // rows. The test policy admits two holds per caller, so exactly one of
    // these may commit.
    let other_north = first_slot(&fx, OFFERING, 210, 400).await;
    let review = first_slot(&fx, SECOND_OFFERING, 90, 200).await;
    let north_hold = tokio::spawn(send(
        fx.http.clone(),
        "POST".to_owned(),
        "/v1/holds".to_owned(),
        caller.clone(),
        Some("ceiling-north".to_owned()),
        Some(admission(&fx, OFFERING, other_north)),
    ));
    let review_hold = tokio::spawn(send(
        fx.http.clone(),
        "POST".to_owned(),
        "/v1/holds".to_owned(),
        caller.clone(),
        Some("ceiling-review".to_owned()),
        Some(admission(&fx, SECOND_OFFERING, review)),
    ));
    let answers = [
        north_hold.await.expect("the first hold answers"),
        review_hold.await.expect("the second hold answers"),
    ];
    let created = answers
        .iter()
        .filter(|(status, _)| *status == StatusCode::CREATED)
        .count();
    let refused: Vec<&Value> = answers
        .iter()
        .filter(|(status, _)| *status == StatusCode::CONFLICT)
        .map(|(_, answer)| answer)
        .collect();
    assert_eq!(
        created, 1,
        "one of the two concurrent holds reaches the ceiling: {answers:?}"
    );
    assert_eq!(
        refused.len(),
        1,
        "the hold over the ceiling is refused: {answers:?}"
    );
    assert_eq!(refused[0]["code"], "capacity.exhausted");
    assert_eq!(
        active_holds(&fx).await,
        2,
        "the caller never holds more than the policy admits"
    );

    // The same ceiling in sequence, so the concurrent refusal above is the
    // ceiling and not a coincidence of the race.
    let later = first_slot(&fx, OFFERING, 500, 700).await;
    let (status, problem) = fx
        .post(
            "/v1/holds",
            &caller,
            "ceiling-third",
            admission(&fx, OFFERING, later),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "capacity.exhausted");
    assert_eq!(active_holds(&fx).await, 2);
}

/// How many rows each table the retention sweep must not touch currently
/// holds, in one reading, so a sweep can be shown to have left every one of
/// them exactly as it found them.
async fn committed_row_counts(fx: &Fixture) -> Vec<(&'static str, i64)> {
    let mut counts = Vec::new();
    for table in [
        "scheduling_claims",
        "scheduling_history",
        "scheduling_outbox",
        "scheduling_audit_outbox",
    ] {
        let count: i64 = fx
            .admin
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap_or_else(|_| panic!("count {table}"))
            .get(0);
        counts.push((table, count));
    }
    counts
}

/// What the retention sweep erases, and just as much what it does not. The
/// deployment advertises one retention period, for idempotency receipts, and
/// the sweep enforces that one plus the fifteen minutes the listing contract
/// gives a cursor. Appointments, their history, the delivery outbox and the
/// audit journal have no retention period in this milestone and the sweep
/// passes over them, by decision rather than omission; this test is what
/// stops the single configured knob from quietly growing into a promise to
/// erase committed scheduling data.
#[tokio::test]
async fn the_retention_sweep_erases_its_two_tables_and_leaves_the_rest_standing() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let booking = json!({"hold": null, "admission": admission(&fx, OFFERING, slot)});
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "retention-1",
            booking.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let appointment_id = appointment["appointmentId"].as_str().unwrap().to_owned();
    let (status, page) = fx.get("/v1/services?limit=1", &fx.reader).await;
    assert_eq!(status, StatusCode::OK);
    let cursor = page["nextCursor"]
        .as_str()
        .expect("the first page mints a cursor")
        .to_owned();
    let committed = committed_row_counts(&fx).await;
    assert!(
        committed.iter().all(|(_, count)| *count > 0),
        "the booking wrote to every table the sweep must not touch: {committed:?}"
    );

    // Long past the cursor's fifteen minutes and the receipt period the
    // fixture deploys.
    let after = Utc::now() + TimeDelta::days(8);
    assert_eq!(
        fx.store
            .erase_expired_cursors(after)
            .await
            .expect("the cursor retention pass runs"),
        1,
        "the one expired cursor is erased"
    );
    assert_eq!(
        fx.store
            .erase_expired_attempts(after)
            .await
            .expect("the receipt retention pass runs"),
        1,
        "the one expired receipt is erased"
    );

    // A cursor is erased outright, so what the caller is told is that the
    // token no longer names a listing. The row is gone, so nothing
    // distinguishes a cursor swept past its expiry from one that never
    // existed; a caller that waited is told to restart the listing either
    // way.
    let (status, problem) = fx
        .get(&format!("/v1/services?limit=1&cursor={cursor}"), &fx.reader)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem["code"], "cursor.invalid");
    let cursors: i64 = fx
        .admin
        .query_one("SELECT count(*) FROM scheduling_cursors", &[])
        .await
        .expect("count the cursors")
        .get(0);
    assert_eq!(cursors, 0, "an erased cursor leaves no row behind");

    // A receipt is tombstoned, not deleted: the row keeps the key and the
    // request it answered and drops only the answer, so the key stays spent.
    let attempt = fx
        .admin
        .query_one(
            "SELECT count(*), count(receipt), count(erased_at) FROM scheduling_attempts",
            &[],
        )
        .await
        .expect("read the swept attempt row");
    assert_eq!(attempt.get::<_, i64>(0), 1, "the attempt row is kept");
    assert_eq!(attempt.get::<_, i64>(1), 0, "the answer is dropped");
    assert_eq!(attempt.get::<_, i64>(2), 1, "the row is stamped erased");
    let (status, problem) = fx
        .post("/v1/appointments", &fx.agent, "retention-1", booking)
        .await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(problem["code"], "idempotency.expired");

    // Everything the deployment committed is still there, and the
    // appointment still reads back.
    assert_eq!(
        committed_row_counts(&fx).await,
        committed,
        "the sweep erased no committed scheduling data"
    );
    let (status, fetched) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &fx.agent)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched["state"], "confirmed");

    // Running the sweep again erases nothing: both passes are idempotent, so
    // a tick that overlaps the previous one cannot double-count its work.
    assert_eq!(
        fx.store
            .erase_expired_cursors(after)
            .await
            .expect("the cursor retention pass runs"),
        0
    );
    assert_eq!(
        fx.store
            .erase_expired_attempts(after)
            .await
            .expect("the receipt retention pass runs"),
        0
    );
}

/// The environment variable the publication tests key their audit chain from,
/// and the master secret they put in it: a test constant like the token
/// signing secret above, never a deployment value. The platform profile
/// refuses anything shorter than 32 bytes.
const AUDIT_SECRET_ENV: &str = "SCHEDULING_TEST_AUDIT_CHAIN_SECRET";
const AUDIT_SECRET: &str = "scheduling-test-audit-chain-secret";

/// Every envelope the journal retains, in the order it was written.
fn retained(path: &std::path::Path) -> Vec<AuditEnvelope> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("a retained audit envelope"))
        .collect()
}

/// One whole deployment life over the same journal: bootstrap the retained
/// chain under the deployment key, recover the append/mark gap from its tail,
/// drain what the store holds, and put the journal down again. Returns how
/// many envelopes the journal retains afterwards.
///
/// The sink is a single-writer sink, so dropping it at the end is what makes
/// the next call a restart rather than a second writer forking the chain.
async fn publish_one_life(fx: &Fixture, path: &std::path::Path) -> usize {
    let profile = AuditProfile::production_from_env(AUDIT_SECRET_ENV).expect("the audit profile");
    let sink = Arc::new(JsonlFileSink::new_single_writer(path).expect("the audit journal sink"));
    let chain = Arc::new(
        profile
            .bootstrap_or_start_empty(sink.as_ref())
            .await
            .expect("bootstrap the retained chain under the deployment key"),
    );
    let mut state = AuditPublicationState::from_verified_tail(
        sink.last_envelope()
            .await
            .expect("read the retained tail")
            .as_ref(),
    );
    let publisher = AuditPublisher {
        store: fx.store.clone(),
        chain,
        sink,
    };
    publish_audit_pass(&publisher, &mut state)
        .await
        .expect("the publication pass runs");
    drop(publisher);
    retained(path).len()
}

/// The audit journal is published in the order it was written. The publisher
/// appends what the store hands it to a hash chain, so the order it reads in
/// is the order the chain goes on to attest to. An event id is a random UUID
/// and sorts in no order at all; these rows are written under identifiers
/// that sort against the order they were written, so a reader ordering by
/// identifier hands them back reversed.
#[tokio::test]
async fn the_audit_journal_is_read_in_the_order_it_was_written() {
    let fx = fixture().await;
    let written: Vec<Uuid> = (0..6)
        .map(|position| {
            Uuid::parse_str(&format!("{:08x}-0000-4000-8000-000000000000", 5 - position))
                .expect("a well-formed test event identifier")
        })
        .collect();
    for (position, event_id) in written.iter().enumerate() {
        fx.store
            .record_refusal_audit(*event_id, json!({"marker": position}))
            .await
            .expect("record one refusal in the journal");
    }

    let pending = fx
        .store
        .pending_audit(100)
        .await
        .expect("read the pending journal");
    let ours: Vec<Uuid> = pending
        .iter()
        .map(|(event_id, _)| *event_id)
        .filter(|event_id| written.contains(event_id))
        .collect();
    assert_eq!(
        ours, written,
        "the journal reads back in the order it was written"
    );
}

/// DB-12: the keyed audit chain survives the process that built it. A
/// deployment stops and starts again over the same retained journal, and the
/// first record of the second life links to the last record of the first: the
/// chain is one unbroken sequence from genesis, with exactly one record that
/// has no predecessor. A restart that forgot the retained chain would start
/// again at genesis and leave the earlier records unattested.
#[tokio::test]
async fn the_audit_chain_continues_across_a_restart() {
    std::env::set_var(AUDIT_SECRET_ENV, AUDIT_SECRET);
    let fx = fixture().await;
    let journal = tempfile::tempdir().expect("a temporary audit journal");
    let path = journal.path().join("audit.jsonl");

    booked(&fx, 90, 200, "chain-first").await;
    let first_life = publish_one_life(&fx, &path).await;
    assert!(first_life > 0, "the commitment wrote records to publish");
    assert!(
        fx.store
            .pending_audit(100)
            .await
            .expect("read the pending journal")
            .is_empty(),
        "a completed pass leaves nothing pending"
    );

    // The process stops. A second life over the same journal commits more and
    // publishes it.
    booked(&fx, 300, 440, "chain-second").await;
    let second_life = publish_one_life(&fx, &path).await;
    assert!(
        second_life > first_life,
        "the second life appended its own records"
    );

    let envelopes = retained(&path);
    assert_eq!(envelopes.len(), second_life);
    assert!(
        envelopes[0].prev_hash.is_none(),
        "the journal reaches genesis exactly once"
    );
    for pair in envelopes.windows(2) {
        assert_eq!(
            pair[1].prev_hash,
            Some(pair[0].record_hash),
            "every envelope links to the one before it"
        );
    }
    assert_eq!(
        envelopes[first_life].prev_hash,
        Some(envelopes[first_life - 1].record_hash),
        "the second life continues the chain the first life left"
    );

    // Every record is retained exactly once, and carries the identity the
    // store knows it by.
    let identities: Vec<&str> = envelopes
        .iter()
        .filter_map(|envelope| envelope.record["eventId"].as_str())
        .collect();
    assert_eq!(
        identities.len(),
        envelopes.len(),
        "every retained envelope carries its event id"
    );
    assert_eq!(
        identities
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<&str>>()
            .len(),
        identities.len(),
        "no record is retained twice"
    );

    // A crash between the append and the mark: the tail is retained but the
    // store still lists it pending. The next life re-marks it from the
    // retained tail rather than appending it a second time.
    let tail = Uuid::parse_str(
        envelopes.last().expect("a retained tail").record["eventId"]
            .as_str()
            .expect("the tail carries its event id"),
    )
    .expect("a parseable event identifier");
    fx.admin
        .execute(
            "UPDATE scheduling_audit_outbox SET published_at=NULL WHERE event_id=$1",
            &[&tail],
        )
        .await
        .expect("reopen the append and mark gap");
    let reconciled = publish_one_life(&fx, &path).await;
    assert_eq!(
        reconciled, second_life,
        "the record retained before the crash is not appended again"
    );
    assert!(
        fx.store
            .pending_audit(100)
            .await
            .expect("read the pending journal")
            .is_empty(),
        "it is marked published instead"
    );
}

/// How one intent stands after a dispatch pass: the state written back, how
/// many attempts it has consumed, and whether its next attempt is held behind
/// a back-off.
async fn intent_state(fx: &Fixture, claim_id: &str) -> (String, i32, bool) {
    let claim = Uuid::parse_str(claim_id).expect("a claim identifier");
    let row = fx
        .admin
        .query_one(
            "SELECT delivery_state, attempts, next_attempt_at > now() \
             FROM scheduling_outbox WHERE claim_id=$1 AND purpose='confirmation'",
            &[&claim],
        )
        .await
        .expect("read one intent back");
    (row.get(0), row.get(1), row.get(2))
}

/// A dispatch pass sends every due intent to the configured destination and
/// reads each answer back the way the classes say: a taken event is delivered
/// and never sent twice, a destination that could not answer proves nothing
/// and waits out a back-off, and an outright refusal is held for an operator
/// rather than retried against a destination that has already said no.
///
/// The destination is a local server this test controls, because what the
/// deployment puts on the wire, and what it concludes from an answer, cannot
/// be observed without one that answers.
#[tokio::test]
async fn a_dispatch_pass_delivers_retries_and_holds_by_what_the_destination_answers() {
    let destination = MockServer::start().await;
    let fx = fixture().await;
    let (taken, _) = booked(&fx, 90, 200, "dispatch-taken").await;
    let (unanswered, _) = booked(&fx, 300, 440, "dispatch-unanswered").await;
    let (refused, _) = booked(&fx, 600, 800, "dispatch-refused").await;

    // One stub per appointment, matched on the identity the event carries, so
    // a single pass produces all three outcomes against one destination.
    for (appointment, status) in [(&taken, 202), (&unanswered, 503), (&refused, 403)] {
        Mock::given(method("POST"))
            .and(path("/events"))
            .and(header("content-type", "application/cloudevents+json"))
            .and(body_string_contains(appointment.as_str()))
            .respond_with(ResponseTemplate::new(status))
            .mount(&destination)
            .await;
    }

    // The destination declares no bearer reference, so nothing is resolved;
    // the resolver still has to exist, and refuses to be built with no
    // provider enabled at all.
    let secrets = SecretResolver::new([SecretProvider::Environment], std::path::Path::new(""))
        .expect("a resolver this destination asks nothing of");
    let transport = reminder_transport(
        &ReminderDestinationConfig {
            url: format!("{}/events", destination.uri()),
            bearer_token_ref: None,
        },
        &secrets,
    )
    .expect("the configured destination compiles into a frozen transport");

    dispatch_due_intents(&fx.store, SCHEDULING_ID, Some(&transport))
        .await
        .expect("the dispatch pass runs");

    assert_eq!(
        intent_state(&fx, &taken).await,
        ("delivered".to_owned(), 1, false),
        "a destination that took the event leaves nothing to retry"
    );
    let (state, attempts, backed_off) = intent_state(&fx, &unanswered).await;
    assert_eq!(
        (state.as_str(), attempts),
        ("pending", 1),
        "a destination that could not answer proves nothing"
    );
    assert!(backed_off, "so the next attempt waits out a back-off");
    assert_eq!(
        intent_state(&fx, &refused).await,
        ("failed".to_owned(), 1, false),
        "a destination that refused outright is held for an operator"
    );

    // What went on the wire is one CloudEvents 1.0 event per intent, naming
    // this deployment and carrying the committed payload, and nothing else.
    let sent = destination.received_requests().await.expect("the requests");
    assert_eq!(sent.len(), 3, "one request per due intent, and no more");
    let event: Value = serde_json::from_slice(
        &sent
            .iter()
            .find(|request| String::from_utf8_lossy(&request.body).contains(taken.as_str()))
            .expect("the taken appointment's event")
            .body,
    )
    .expect("a JSON event body");
    assert_eq!(event["specversion"], "1.0");
    assert_eq!(event["source"], SCHEDULING_ID);
    assert_eq!(event["type"], "org.registrystack.scheduling.confirmation");
    assert_eq!(event["data"]["appointmentId"], taken);

    // A second pass repeats nothing: the delivered intent is done and the
    // other two are held or backed off, so the destination hears no more.
    dispatch_due_intents(&fx.store, SCHEDULING_ID, Some(&transport))
        .await
        .expect("the second dispatch pass runs");
    assert_eq!(
        destination
            .received_requests()
            .await
            .expect("the requests")
            .len(),
        3,
        "nothing a pass concluded is sent to the destination again"
    );
}

/// The arrival-window offering and the window it serves, added to the test
/// policy. Both are only in the policies that ask for them: the exact-time
/// fixtures publish no window, so no test pays for supply it never reads.
const WINDOW_OFFERING: &str = "registry-arrivals";
const WINDOW_ID: &str = "morning-arrivals";
/// The window's own revision, deliberately not the policy revision, so a
/// request that sends one where the other belongs is caught rather than
/// accepted by coincidence.
const WINDOW_REVISION: u64 = 3;

/// The test policy with one arrival offering that references the window ID
/// owned by the runtime records.
fn policy_with_window() -> String {
    POLICY.replace(
        "holdPolicy:",
        &format!(
            "  - id: {WINDOW_OFFERING}\n\
             \x20   service: registry-update\n\
             \x20   label: Counter arrivals\n\
             \x20   mode: arrival-window\n\
             \x20   location: north-counter\n\
             \x20   because: test\n\
             \x20   cancellationCutoffMinutes: 240\n\
             \x20   arrival:\n\
             \x20     window: {WINDOW_ID}\n\
             \x20     leadTimeMinutes: 0\n\
             \x20     horizonDays: 60\n\
             \x20   requiresCapabilities: []\n\
             \x20   prerequisites: []\n\
             holdPolicy:",
        ),
    )
}

const FOREIGN_WINDOW_OFFERING: &str = "registry-review-arrivals";

fn policy_with_shared_window() -> String {
    policy_with_window().replace(
        "holdPolicy:",
        &format!(
            "  - id: {FOREIGN_WINDOW_OFFERING}\n\
             \x20   service: registry-review\n\
             \x20   label: Review arrivals\n\
             \x20   mode: arrival-window\n\
             \x20   location: north-counter\n\
             \x20   because: test\n\
             \x20   cancellationCutoffMinutes: 240\n\
             \x20   arrival:\n\
             \x20     window: {WINDOW_ID}\n\
             \x20     leadTimeMinutes: 60\n\
             \x20     horizonDays: 60\n\
             \x20   requiresCapabilities: []\n\
             \x20   prerequisites: []\n\
             holdPolicy:"
        ),
    )
}

/// The operator records that publish one concrete arrival window.
fn records_with_window(start: DateTime<Utc>) -> SchedulingFacts {
    let mut facts = records_without(&[]);
    facts.windows.push(PublishedWindow {
        id: WINDOW_ID.to_owned(),
        revision: WINDOW_REVISION,
        offering: WINDOW_OFFERING.to_owned(),
        location: "north-counter".to_owned(),
        start,
        end: start + TimeDelta::hours(2),
        units: 2,
        units_policy: RequiredUnitsPolicy::Fixed {
            units: 1,
            because: "test".to_owned(),
        },
        subquotas: vec![WindowSubquota {
            id: "assisted-quota".to_owned(),
            channel: Channel::Assisted,
            units: 1,
            because: "test".to_owned(),
        }],
        leftover: None,
        staffing: None,
        because: "test".to_owned(),
    });
    facts
}

async fn fixture_with_window(start: DateTime<Utc>) -> Fixture {
    fixture_with_window_records(records_with_window(start)).await
}

async fn fixture_with_window_records(facts: SchedulingFacts) -> Fixture {
    let fx = fixture_publishing(
        &policy_with_window(),
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;
    fx.store
        .replace_facts(SCHEDULING_ID, &facts, Uuid::new_v4(), operator_audit())
        .await
        .expect("publish the window records");
    fx
}

/// One direct-create body admitting an arrival on the window, on `channel`
/// when it names one.
fn arrival(fx: &Fixture, start: DateTime<Utc>, channel: Option<&str>) -> Value {
    json!({"hold": null, "admission": {
        "offering": WINDOW_OFFERING,
        "start": stamp(start),
        "party": {"recipients": 1, "attendees": 1},
        "channel": channel,
        "duplicateKey": null,
        "policyRevision": fx.revision,
        "windowRevision": WINDOW_REVISION,
        "capabilities": [],
        "prerequisites": [],
    }})
}

/// The window entry availability lists for the window offering, if any.
async fn window_entry(fx: &Fixture, from_minutes: i64, to_minutes: i64) -> Option<Value> {
    let (status, page) = fx
        .get(
            &availability_uri(WINDOW_OFFERING, from_minutes, to_minutes),
            &fx.reader,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "availability answers over a window");
    page["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| entry["kind"] == "window")
        .cloned()
}

#[tokio::test]
async fn records_replacement_refuses_to_move_a_window_with_standing_commitments() {
    let day = (Utc::now() + TimeDelta::days(2)).date_naive();
    let start = DateTime::<Utc>::from_naive_utc_and_offset(
        day.and_hms_opt(9, 0, 0).expect("a morning instant"),
        Utc,
    );
    let fx = fixture_with_window(start).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "window-publication-standing",
            arrival(&fx, start, None),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");

    let mut moved = records_with_window(start);
    moved.windows[0].start += TimeDelta::days(1);
    moved.windows[0].end += TimeDelta::days(1);
    let refusal = fx
        .store
        .replace_facts(SCHEDULING_ID, &moved, Uuid::new_v4(), operator_audit())
        .await
        .expect_err("a moved window cannot strand a standing appointment");
    assert!(refusal.to_string().contains(WINDOW_ID), "{refusal}");
}

#[tokio::test]
async fn changed_window_records_must_advance_the_revision_even_after_removal() {
    let start = (Utc::now() + TimeDelta::days(2))
        .with_nanosecond(0)
        .expect("second precision");
    let fx = fixture_with_window(start).await;
    let (initial, facts_revision) = fx.store.facts().await.expect("the initial records");
    let audit_rows = fx
        .store
        .pending_audit(100)
        .await
        .expect("the initial audit rows")
        .len();

    let mut changed = records_with_window(start);
    changed.windows[0].end += TimeDelta::minutes(30);
    for proposed_revision in [WINDOW_REVISION, WINDOW_REVISION - 1] {
        changed.windows[0].revision = proposed_revision;
        let refusal = fx
            .store
            .replace_facts(SCHEDULING_ID, &changed, Uuid::new_v4(), operator_audit())
            .await
            .expect_err("changed terms must advance their public revision");
        assert!(matches!(
            refusal,
            StoreError::WindowRevision {
                current: WINDOW_REVISION,
                proposed,
                ..
            } if proposed == proposed_revision
        ));
    }
    let (after_refusals, after_refusal_revision) = fx
        .store
        .facts()
        .await
        .expect("the refused records roll back");
    assert_eq!(after_refusals, initial);
    assert_eq!(after_refusal_revision, facts_revision);
    assert_eq!(
        fx.store
            .pending_audit(100)
            .await
            .expect("the audit rows after refusal")
            .len(),
        audit_rows,
        "a refused replacement writes no allowed audit row"
    );

    changed.windows[0].revision = WINDOW_REVISION + 1;
    fx.store
        .replace_facts(SCHEDULING_ID, &changed, Uuid::new_v4(), operator_audit())
        .await
        .expect("an advanced revision accepts changed terms");
    fx.store
        .replace_facts(
            SCHEDULING_ID,
            &records_without(&[]),
            Uuid::new_v4(),
            operator_audit(),
        )
        .await
        .expect("the idle window may be removed");
    let (_, removed_revision) = fx.store.facts().await.expect("the removed records");
    let removed_audit_rows = fx
        .store
        .pending_audit(100)
        .await
        .expect("the audit rows after removal")
        .len();

    let mut republished = changed.clone();
    republished.windows[0].end += TimeDelta::minutes(30);
    for proposed_revision in [WINDOW_REVISION + 1, WINDOW_REVISION] {
        republished.windows[0].revision = proposed_revision;
        let refusal = fx
            .store
            .replace_facts(
                SCHEDULING_ID,
                &republished,
                Uuid::new_v4(),
                operator_audit(),
            )
            .await
            .expect_err("removal does not erase the revision high-water mark");
        assert!(matches!(
            refusal,
            StoreError::WindowRevision {
                current,
                proposed,
                ..
            } if current == WINDOW_REVISION + 1 && proposed == proposed_revision
        ));
    }
    let (still_removed, after_republish_refusal) = fx
        .store
        .facts()
        .await
        .expect("the refused republication rolls back");
    assert!(still_removed.windows.is_empty());
    assert_eq!(after_republish_refusal, removed_revision);
    assert_eq!(
        fx.store
            .pending_audit(100)
            .await
            .expect("the audit rows after republication refusal")
            .len(),
        removed_audit_rows
    );

    republished.windows[0].revision = WINDOW_REVISION + 2;
    fx.store
        .replace_facts(
            SCHEDULING_ID,
            &republished,
            Uuid::new_v4(),
            operator_audit(),
        )
        .await
        .expect("an advanced revision may republish the identifier");
    fx.store
        .replace_facts(
            SCHEDULING_ID,
            &republished,
            Uuid::new_v4(),
            operator_audit(),
        )
        .await
        .expect("an exact unchanged reapply remains accepted");
}

#[tokio::test]
async fn a_window_record_must_belong_to_the_authorized_offering_and_location() {
    let start = (Utc::now() + TimeDelta::hours(3))
        .with_nanosecond(0)
        .expect("second precision");
    let fx = fixture_publishing(
        &policy_with_shared_window(),
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;
    fx.store
        .replace_facts(
            SCHEDULING_ID,
            &records_with_window(start),
            Uuid::new_v4(),
            operator_audit(),
        )
        .await
        .expect("seed the intentionally misbound operator record");
    let caller = agent_token_for_service("registry-review");
    let mut request = arrival(&fx, start, None);
    request["admission"]["offering"] = json!(FOREIGN_WINDOW_OFFERING);

    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &caller,
            "foreign-window-offering",
            request.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{problem}");
    assert_eq!(problem["code"], "service.unavailable");

    let mut wrong_location = records_with_window(start);
    wrong_location.windows[0].revision = WINDOW_REVISION + 1;
    wrong_location.windows[0].offering = FOREIGN_WINDOW_OFFERING.to_owned();
    wrong_location.windows[0].location = "two-counter".to_owned();
    fx.store
        .replace_facts(
            SCHEDULING_ID,
            &wrong_location,
            Uuid::new_v4(),
            operator_audit(),
        )
        .await
        .expect("seed the intentionally wrong-location operator record");
    request["admission"]["windowRevision"] = json!(WINDOW_REVISION + 1);
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &caller,
            "foreign-window-location",
            request,
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{problem}");
    assert_eq!(problem["code"], "service.unavailable");

    let claims: i64 = fx
        .admin
        .query_one("SELECT count(*) FROM scheduling_claims", &[])
        .await
        .expect("count the claims")
        .get(0);
    assert_eq!(claims, 0, "misbound records never reach a commitment");
}

#[tokio::test]
async fn a_location_closure_hides_and_refuses_an_arrival_window() {
    let day = (Utc::now() + TimeDelta::days(2)).date_naive();
    let start = DateTime::<Utc>::from_naive_utc_and_offset(
        day.and_hms_opt(9, 0, 0).expect("a morning instant"),
        Utc,
    );
    let fx = fixture_with_window(start).await;
    let mut facts = records_with_window(start);
    facts.exceptions.push(CalendarExceptionRecord {
        id: "counter-closure".to_owned(),
        location: "north-counter".to_owned(),
        kind: ExceptionRecordKind::Closure,
        date: day.to_string(),
        start_time: "08:00".to_owned(),
        end_time: "12:00".to_owned(),
        reopens: None,
        authority: None,
    });
    fx.store
        .replace_facts(SCHEDULING_ID, &facts, Uuid::new_v4(), operator_audit())
        .await
        .expect("apply the location closure");

    assert!(
        window_entry(&fx, 60, 4_000).await.is_none(),
        "a closed window is not published as availability"
    );
    let (status, refused) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-closed",
            arrival(&fx, start, None),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["code"], "location.closed");
}

#[tokio::test]
async fn policy_publication_refuses_to_remove_an_offering_with_a_live_appointment() {
    let fx = fixture().await;
    let (appointment_id, revision) = booked(&fx, 300, 440, "retained-offering-create").await;
    let current = parse_policy_yaml(POLICY).expect("the current policy");
    let mut replacement = current.clone();
    replacement.scheduling.version += 1;
    replacement
        .offerings
        .retain(|offering| offering.id != OFFERING);
    let digest = replacement.policy_digest();
    let mut pool_ids: Vec<String> = replacement
        .offerings
        .iter()
        .filter_map(|offering| offering.exact_time.as_ref().map(|exact| exact.pool.clone()))
        .collect();
    pool_ids.sort();
    pool_ids.dedup();

    let refusal = fx
        .store
        .apply_policy(SCHEDULING_ID, &digest, &pool_ids, &replacement)
        .await
        .expect_err("a live appointment keeps its offering operable");
    assert!(refusal.to_string().contains(OFFERING), "{refusal}");

    let (status, cancelled) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/cancel"),
            &fx.agent,
            "retained-offering-cancel",
            json!({"observedRevision": revision, "reason": null}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");
    assert_eq!(cancelled["state"], "cancelled");
}

#[tokio::test]
async fn policy_publication_refuses_to_move_an_active_offering_between_pools() {
    let fx = fixture().await;
    booked(&fx, 300, 440, "retained-offering-pool-create").await;
    let mut replacement = parse_policy_yaml(POLICY).expect("the current policy");
    replacement.scheduling.version += 1;
    replacement
        .offerings
        .iter_mut()
        .find(|offering| offering.id == OFFERING)
        .and_then(|offering| offering.exact_time.as_mut())
        .expect("the exact-time offering")
        .pool = "two-counter".to_owned();
    let digest = replacement.policy_digest();

    let refusal = fx
        .store
        .apply_policy(
            SCHEDULING_ID,
            &digest,
            &["north-counter".to_owned(), "two-counter".to_owned()],
            &replacement,
        )
        .await
        .expect_err("an active offering cannot move to different supply");
    assert!(refusal.to_string().contains("supply"), "{refusal}");
}

/// An arrival window is a second admission mode with a ledger of its own: its
/// claims occupy the window rather than a member of a pool, its capacity is
/// counted in units rather than in slots, and a channel subquota is a ceiling
/// inside the window's total. Nothing in the database suite had ever booked
/// one, so none of that was covered against a real ledger.
///
/// The window here carries two units, one of them reserved to the assisted
/// channel. The assisted caller takes that one, the next assisted caller is
/// refused on the subquota while the window still has a unit left, a public
/// caller takes the last unit, and the window then offers nothing.
#[tokio::test]
async fn an_arrival_window_allocates_its_units_and_holds_its_channel_ceiling() {
    // The published interval is stamped to the second, which is the precision
    // every comparison below reads it back at.
    let start = (Utc::now() + TimeDelta::hours(3))
        .with_nanosecond(0)
        .expect("second precision");
    let fx = fixture_with_window(start).await;

    let offered = window_entry(&fx, 60, 300)
        .await
        .expect("the published window is offered");
    assert_eq!(offered["window"], WINDOW_ID);
    assert_eq!(offered["start"], stamp(start));
    assert_eq!(offered["remaining"], 2, "the whole window is unallocated");

    let (status, mismatch) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-wrong-start",
            arrival(&fx, start + TimeDelta::minutes(15), None),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{mismatch}");
    assert_eq!(mismatch["code"], "schedule.unpublished");

    // The assisted channel holds one of the two units.
    let (status, booked) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-assisted",
            arrival(&fx, start, Some("assisted")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{booked}");
    assert_eq!(booked["start"], stamp(start));
    assert_eq!(booked["end"], stamp(start + TimeDelta::hours(2)));
    // An arrival joins a window, so there is no member to name. The field is
    // the pool member an exact-time booking occupies, and the ledger's one
    // supply column must not be reported through it as if it were one.
    assert!(
        booked["resource"].is_null(),
        "an arrival names no resource: {booked}"
    );

    // The window still has a unit, but the assisted subquota does not, so a
    // second assisted arrival is refused on the ceiling inside the total.
    let (status, refused) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-assisted-again",
            arrival(&fx, start, Some("assisted")),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["code"], "capacity.exhausted");
    assert_eq!(
        window_entry(&fx, 60, 300).await.expect("still offered")["remaining"],
        1,
        "the window's own total is what availability reports"
    );

    // The same unit the assisted caller could not have is free to a public
    // one, and it is the window's last.
    let (status, last) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-public",
            arrival(&fx, start, Some("public")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{last}");
    let (status, exhausted) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-too-late",
            arrival(&fx, start, None),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{exhausted}");
    assert_eq!(exhausted["code"], "capacity.exhausted");
    assert!(
        window_entry(&fx, 60, 300).await.is_none(),
        "a window with no units left is not offered"
    );

    // A window claim occupies the window, not a member of a pool. The ledger
    // holds both in one `supply_id` column, which carries the resource an
    // exact-time claim books and the window an arrival claim joins, so the
    // column means two things and only the claim's offering says which.
    let occupied: Vec<(String, Option<String>)> = fx
        .admin
        .query(
            "SELECT supply_id, channel FROM scheduling_claims \
             WHERE state='active' AND offering=$1 ORDER BY created_at",
            &[&WINDOW_OFFERING],
        )
        .await
        .expect("read the window's claims")
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(
        occupied,
        vec![
            (WINDOW_ID.to_owned(), Some("assisted".to_owned())),
            (WINDOW_ID.to_owned(), Some("public".to_owned())),
        ],
        "both arrivals occupy the window itself, each under its own channel"
    );

    // The window revision is the caller's agreement about the window, and a
    // stale one is refused whatever the policy revision says.
    let mut stale = arrival(&fx, start, None);
    stale["admission"]["windowRevision"] = json!(WINDOW_REVISION - 1);
    let (status, mismatch) = fx
        .post("/v1/appointments", &fx.agent, "arrival-stale", stale)
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{mismatch}");
    assert_eq!(mismatch["code"], "revision.mismatch");
}

#[tokio::test]
async fn an_arrival_reschedule_persists_its_new_units_and_channel() {
    let start = (Utc::now() + TimeDelta::hours(3))
        .with_nanosecond(0)
        .expect("second precision");
    let mut facts = records_with_window(start);
    facts.windows[0].units = 6;
    facts.windows[0].units_policy = RequiredUnitsPolicy::PerRecipient {
        per_recipient: 1,
        because: "test".to_owned(),
    };
    let fx = fixture_with_window_records(facts).await;

    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-resize-create",
            arrival(&fx, start, Some("assisted")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    assert_eq!(appointment["units"], 1);
    assert_eq!(appointment["channel"], "assisted");
    let appointment_id = appointment["appointmentId"]
        .as_str()
        .expect("an appointment identifier");
    let observed_revision = appointment["revision"]
        .as_u64()
        .expect("an appointment revision");

    let mut moved_admission = arrival(&fx, start, Some("public"))["admission"].clone();
    moved_admission["party"] = json!({"recipients": 5, "attendees": 5});
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "arrival-resize-move",
            json!({
                "observedRevision": observed_revision,
                "admission": moved_admission,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["units"], 5);
    assert_eq!(moved["channel"], "public");

    let stored = fx
        .admin
        .query_one(
            "SELECT units, channel FROM scheduling_claims WHERE claim_id=$1",
            &[&Uuid::parse_str(appointment_id).expect("a stored appointment identifier")],
        )
        .await
        .expect("read the rescheduled allocation");
    assert_eq!(stored.get::<_, i32>(0), 5);
    assert_eq!(
        stored.get::<_, Option<String>>(1).as_deref(),
        Some("public")
    );

    // Moving out of the assisted channel frees that subquota, while the five
    // recalculated units leave exactly one unit in the window's total.
    let (status, last) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-resize-last-unit",
            arrival(&fx, start, Some("assisted")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{last}");
    assert_eq!(last["channel"], "assisted");
    assert!(
        window_entry(&fx, 60, 300).await.is_none(),
        "the resized appointment and final assisted unit exhaust the window"
    );

    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-resize-over-capacity",
            arrival(&fx, start, Some("public")),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "capacity.exhausted");
}

// ---------------------------------------------------------------------------
// Concurrency and ownership regressions
// ---------------------------------------------------------------------------

/// COR-3. Two lifecycle writers that accepted the same observed revision
/// must not both commit. The observed revision and the active state guard
/// the UPDATE itself, so one transition lands and the losing writer's whole
/// transaction rolls back behind a revision mismatch, whatever order the
/// two arrive in.
#[tokio::test]
async fn competing_cancellations_commit_exactly_one_transition() {
    let fx = fixture().await;
    let (appointment, revision) = booked(&fx, 300, 440, "race-cancel").await;
    let cancel = |key: &'static str| {
        let http = fx.http.clone();
        let token = fx.agent.clone();
        let uri = format!("/v1/appointments/{appointment}/cancel");
        let body = json!({"observedRevision": revision, "reason": null});
        tokio::spawn(async move {
            send(
                http,
                "POST".into(),
                uri,
                token,
                Some(key.into()),
                Some(body),
            )
            .await
        })
    };
    let (first, second) = tokio::join!(cancel("race-cancel-a"), cancel("race-cancel-b"));
    let mut answers = [
        first.expect("the first cancel answered"),
        second.expect("the second cancel answered"),
    ];
    answers.sort_by_key(|(status, _)| *status);
    assert_eq!(
        answers[0].0,
        StatusCode::OK,
        "exactly one writer wins: {}",
        answers[0].1
    );
    // The loser is refused whichever way it met the moved claim: a
    // revision.mismatch when its fenced write lost the race, or a
    // hold.released when its read landed after the winner committed. Both
    // are coherent refusals of a superseded observation.
    assert!(
        answers[1].0 == StatusCode::PRECONDITION_FAILED || answers[1].0 == StatusCode::CONFLICT,
        "exactly one writer loses: {}",
        answers[1].1
    );
    assert!(answers[1].0.is_client_error());
    // The ledger carries one coherent transition: one lifecycle event, one
    // cancellation intent, and the revision the winner wrote.
    let claim_id = Uuid::parse_str(&appointment).expect("a claim identifier");
    let counts = fx
        .admin
        .query_one(
            "SELECT \
                (SELECT count(*) FROM scheduling_history WHERE claim_id=$1 AND revision=2), \
                (SELECT count(*) FROM scheduling_outbox WHERE claim_id=$1 AND purpose='cancellation'), \
                (SELECT revision FROM scheduling_claims WHERE claim_id=$1)",
            &[&claim_id],
        )
        .await
        .expect("read the committed transition");
    assert_eq!(
        counts.get::<_, i64>(0),
        1,
        "one history event at the next revision"
    );
    assert_eq!(counts.get::<_, i64>(1), 1, "one cancellation intent");
    assert_eq!(
        counts.get::<_, i64>(2),
        2,
        "the revision moved exactly once"
    );
}

/// The same guard coordinates a reschedule against a cancellation: the two
/// writers take different locks, but the claim row's own predicate decides,
/// and the response the caller keeps is the one that actually landed.
#[tokio::test]
async fn a_reschedule_and_a_cancellation_commit_exactly_one_transition() {
    let fx = fixture().await;
    let (appointment, revision) = booked(&fx, 300, 440, "race-mixed").await;
    let other = first_slot(&fx, OFFERING, 480, 620).await;
    let reschedule = {
        let http = fx.http.clone();
        let token = fx.agent.clone();
        let uri = format!("/v1/appointments/{appointment}/reschedule");
        let body = json!({
            "observedRevision": revision,
            "admission": admission(&fx, OFFERING, other),
        });
        tokio::spawn(async move {
            send(
                http,
                "POST".into(),
                uri,
                token,
                Some("race-mixed-move".into()),
                Some(body),
            )
            .await
        })
    };
    let cancel = {
        let http = fx.http.clone();
        let token = fx.agent.clone();
        let uri = format!("/v1/appointments/{appointment}/cancel");
        let body = json!({"observedRevision": revision, "reason": null});
        tokio::spawn(async move {
            send(
                http,
                "POST".into(),
                uri,
                token,
                Some("race-mixed-cancel".into()),
                Some(body),
            )
            .await
        })
    };
    let (moved, cancelled) = tokio::join!(reschedule, cancel);
    let moved = moved.expect("the reschedule answered");
    let cancelled = cancelled.expect("the cancel answered");
    let successes = usize::from(moved.0.is_success()) + usize::from(cancelled.0.is_success());
    assert_eq!(
        successes, 1,
        "exactly one transition commits: {moved:?} {cancelled:?}"
    );
    // Whichever won, the appointment's stored state and its history agree,
    // and no two history events share a revision.
    let claim_id = Uuid::parse_str(&appointment).expect("a claim identifier");
    let duplicates = fx
        .admin
        .query_one(
            "SELECT count(*) FROM (SELECT revision FROM scheduling_history \
             WHERE claim_id=$1 GROUP BY revision HAVING count(*) > 1) AS doubled",
            &[&claim_id],
        )
        .await
        .expect("read the history revisions");
    assert_eq!(
        duplicates.get::<_, i64>(0),
        0,
        "no two history events share a revision"
    );
}

/// SEC-03. The task grant is re-checked against a fresh observation of the
/// clock immediately before the final write: a grant that still stands at
/// the door and lapses before the commit books nothing.
#[tokio::test]
async fn a_grant_that_lapses_before_the_commit_never_books() {
    let fx = fixture().await;
    // The pinned clock sits past the test token's grant expiry, while the
    // request's own now, observed at the door, is still inside it.
    let pinned = Utc::now() + TimeDelta::minutes(20);
    fx.store.pin_clock(Arc::new(move || pinned));
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "lapsed-grant",
            json!({"hold": null, "admission": admission(&fx, OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
    assert_eq!(problem["code"], "operation.not-authorized");
    let committed = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE kind='booking'",
            &[],
        )
        .await
        .expect("read the claim ledger");
    assert_eq!(
        committed.get::<_, i64>(0),
        0,
        "a lapsed grant commits nothing"
    );
}

/// Every mutation must roll back its tentative writes when authorization
/// expires after its admission-time check but before the final commit check.
#[tokio::test]
async fn every_mutation_rechecks_expiry_after_its_writes() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    for operation in [
        "hold",
        "create",
        "confirm",
        "release",
        "reschedule",
        "cancel",
    ] {
        let fx = fixture().await;
        let slot = first_slot(&fx, OFFERING, 480, 620).await;
        let (method, uri, body) = match operation {
            "hold" => (
                "POST",
                "/v1/holds".to_owned(),
                Some(admission(&fx, OFFERING, slot)),
            ),
            "create" => (
                "POST",
                "/v1/appointments".to_owned(),
                Some(json!({"hold": null, "admission": admission(&fx, OFFERING, slot)})),
            ),
            "confirm" | "release" => {
                let (status, hold) = fx
                    .post(
                        "/v1/holds",
                        &fx.agent,
                        "setup",
                        admission(&fx, OFFERING, slot),
                    )
                    .await;
                assert_eq!(status, StatusCode::CREATED, "{hold}");
                let id = hold["holdId"].as_str().expect("a hold identifier");
                if operation == "confirm" {
                    (
                        "POST",
                        "/v1/appointments".to_owned(),
                        Some(json!({"hold": id, "admission": null})),
                    )
                } else {
                    ("DELETE", format!("/v1/holds/{id}"), None)
                }
            }
            "reschedule" | "cancel" => {
                let (id, revision) = booked(&fx, 300, 440, "setup").await;
                if operation == "reschedule" {
                    (
                        "POST",
                        format!("/v1/appointments/{id}/reschedule"),
                        Some(json!({
                            "observedRevision": revision,
                            "admission": admission(&fx, OFFERING, slot),
                        })),
                    )
                } else {
                    (
                        "POST",
                        format!("/v1/appointments/{id}/cancel"),
                        Some(json!({
                            "observedRevision": revision, "reason": null,
                        })),
                    )
                }
            }
            _ => unreachable!(),
        };
        // Compare all transactional business effects, not just the status.
        // A refusal may add its own refused receipt and denied audit event.
        let state = "SELECT jsonb_build_array( \
            (SELECT jsonb_agg(to_jsonb(c) ORDER BY claim_id) FROM scheduling_claims c), \
            (SELECT jsonb_agg(to_jsonb(h) ORDER BY event_id) FROM scheduling_history h), \
            (SELECT jsonb_agg(to_jsonb(o) ORDER BY outbox_id) FROM scheduling_outbox o), \
            (SELECT count(*) FROM scheduling_attempts WHERE status_code BETWEEN 200 AND 299))";
        let before: Value = fx
            .admin
            .query_one(state, &[])
            .await
            .expect("snapshot before mutation")
            .get(0);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let valid = Utc::now();
        fx.store.pin_clock(Arc::new(move || {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                valid
            } else {
                valid + TimeDelta::minutes(20)
            }
        }));
        let (status, problem) = fx
            .request(method, &uri, &fx.agent, Some("expires-after-writes"), body)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{operation}: {problem}");
        assert_eq!(problem["code"], "operation.not-authorized", "{operation}");
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "{operation} observes the final clock"
        );
        let after: Value = fx
            .admin
            .query_one(state, &[])
            .await
            .expect("snapshot after refusal")
            .get(0);
        assert_eq!(after, before, "{operation} rolls back all business writes");
    }
}

/// A running process refuses a commitment even when the caller names the
/// stored revision another process just published: the rules this process
/// evaluates are not the rules that revision names, and the claim is
/// refused rather than stamped with a policy it never saw.
#[tokio::test]
async fn a_stale_process_refuses_even_a_request_under_the_current_revision() {
    let fx = fixture().await;
    let mut replacement = parse_policy_yaml(POLICY).expect("the replacement policy");
    replacement.scheduling.version += 1;
    let replacement_digest = replacement.policy_digest();
    let moved = fx
        .store
        .apply_policy(
            SCHEDULING_ID,
            &replacement_digest,
            &["north-counter".to_owned(), "two-counter".to_owned()],
            &replacement,
        )
        .await
        .expect("publish a second policy revision");
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let mut admission_body = admission(&fx, OFFERING, slot);
    admission_body["policyRevision"] = json!(u64::try_from(moved).expect("a bounded revision"));
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "stale-process-current-revision",
            json!({"hold": null, "admission": admission_body}),
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{problem}");
    assert_eq!(problem["code"], "policy.changed");
}

#[tokio::test]
async fn a_stale_process_can_still_release_an_appointment() {
    let fx = fixture().await;
    let (id, revision) = booked(&fx, 480, 620, "before-policy-change").await;
    let mut replacement = parse_policy_yaml(POLICY).expect("the replacement policy");
    replacement.scheduling.version += 1;
    replacement.offerings[0].cancellation_cutoff_minutes += 1;
    let replacement_digest = replacement.policy_digest();
    fx.store
        .apply_policy(
            SCHEDULING_ID,
            &replacement_digest,
            &["north-counter".to_owned(), "two-counter".to_owned()],
            &replacement,
        )
        .await
        .expect("publish the replacement policy");
    let (status, cancelled) = fx
        .post(
            &format!("/v1/appointments/{id}/cancel"),
            &fx.agent,
            "stale-policy-cancellation",
            json!({"observedRevision": revision, "reason": null}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");
    assert_eq!(cancelled["state"], "cancelled");
    let row = fx
        .admin
        .query_one(
            "SELECT state, revision FROM scheduling_claims WHERE claim_id=$1",
            &[&Uuid::parse_str(&id).expect("appointment id")],
        )
        .await
        .expect("read cancelled appointment");
    assert_eq!(row.get::<_, String>(0), "cancelled");
    assert_eq!(row.get::<_, i64>(1), i64::try_from(revision + 1).unwrap());
}

/// A records replacement moves the records revision under the supply
/// anchor: a commitment whose facts were resolved before the swap is
/// refused whole, rather than naming a resource the deployment retired.
#[tokio::test]
async fn a_records_swap_refuses_a_commitment_resolving_the_old_facts() {
    let fx = fixture().await;
    let policy = parse_policy_yaml(POLICY).expect("the scheduling test policy");
    let offering = policy.offering(OFFERING).expect("the test offering");
    // The slot resolves while the station still stands: the swap retires it.
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let (facts, resolved_under) = fx.store.facts().await.expect("resolve the standing facts");
    let exceptions: Vec<_> = facts
        .exceptions
        .iter()
        .filter(|exception| exception.location == offering.location)
        .map(|exception| exception.borrowed())
        .collect();
    let timezone = facts
        .location(&offering.location)
        .expect("the seeded location")
        .timezone
        .clone();
    let members: Vec<PoolMember> = facts
        .pool(
            &offering
                .exact_time
                .as_ref()
                .expect("an exact-time offering")
                .pool,
        )
        .expect("the seeded pool")
        .members
        .clone();
    let open = location_open_intervals(&policy, &offering.location, &timezone, &exceptions)
        .expect("resolve the openings");
    let closures = location_closure_intervals(&facts, &offering.location, &timezone)
        .expect("resolve the closures");
    // The operator retires the station this offering books; nothing occupies
    // it, so the swap commits.
    let swapped = records_without(&["station-1"]);
    fx.store
        .replace_facts(SCHEDULING_ID, &swapped, Uuid::new_v4(), operator_audit())
        .await
        .expect("the records swap commits");
    let supply = SupplyContext::ExactTime {
        exact: offering
            .exact_time
            .as_ref()
            .expect("an exact-time offering"),
        members: &members,
        open: &open,
        closures: &closures,
    };
    let request = AdmissionRequest {
        offering: OFFERING.to_owned(),
        start: slot,
        party: PartyCounts {
            recipients: 1,
            attendees: 1,
        },
        channel: None,
        duplicate_key: None,
        policy_revision: fx.revision,
        window_revision: None,
        capabilities: Vec::new(),
        prerequisites: Vec::new(),
    };
    let commitment = Commitment {
        now: Utc::now(),
        policy_revision: i64::try_from(fx.revision).expect("a bounded revision"),
        facts_revision: resolved_under,
        actor: "actor-pseudonym",
        actor_issuer: ISSUER,
        actor_subject: "principal-agent",
        idempotency_key: "stale-facts",
        request_hash: "sha256:stale-facts",
        attempt_expires_at: Utc::now() + TimeDelta::days(7),
        grant_exp_unix: None,
        audit_event: Uuid::new_v4(),
        audit_record: operator_audit(),
        hooks: None,
    };
    let outcome = fx
        .store
        .create_appointment(offering, &supply, &request, commitment)
        .await;
    assert!(
        matches!(outcome, Err(CommitError::FactsStale)),
        "a commitment resolving the pre-swap facts is refused: {outcome:?}"
    );
    let committed = fx
        .admin
        .query_one(
            "SELECT count(*) FROM scheduling_claims WHERE kind='booking'",
            &[],
        )
        .await
        .expect("read the claim ledger");
    assert_eq!(
        committed.get::<_, i64>(0),
        0,
        "a stale facts resolution commits nothing"
    );
}

/// The dispatch lease: a claimed intent is not claimable again until its
/// lease passes, and an outcome write only lands for the attempt that owns
/// the intent.
#[tokio::test]
async fn a_claimed_intent_is_leased_and_its_outcome_is_fenced_by_the_attempt() {
    let fx = fixture().await;
    let _ = booked(&fx, 90, 200, "lease-1").await;
    let due = Utc::now() + TimeDelta::days(1);
    let claimed: Vec<_> = fx
        .store
        .claim_due_intents(due, 100, TimeDelta::minutes(10))
        .await
        .expect("the delivery sweep runs")
        .into_iter()
        .filter(|intent| intent.purpose == "reminder")
        .collect();
    assert_eq!(
        claimed.len(),
        1,
        "the commitment minted one reminder intent"
    );
    let row = &claimed[0];
    assert_eq!(row.attempts, 1);

    // Inside the lease a second dispatcher claims nothing of this intent.
    let leased = fx
        .store
        .claim_due_intents(due + TimeDelta::minutes(9), 100, TimeDelta::minutes(10))
        .await
        .expect("the delivery sweep runs");
    assert!(
        leased
            .iter()
            .all(|intent| intent.outbox_id != row.outbox_id),
        "a leased intent is not claimable again"
    );

    // Past the lease the intent is recoverable, as a new attempt.
    let reclaimed: Vec<_> = fx
        .store
        .claim_due_intents(due + TimeDelta::minutes(11), 100, TimeDelta::minutes(10))
        .await
        .expect("the delivery sweep runs")
        .into_iter()
        .filter(|intent| intent.outbox_id == row.outbox_id)
        .collect();
    assert_eq!(reclaimed.len(), 1, "the lease passed, so the intent is due");
    assert_eq!(
        reclaimed[0].attempts, 2,
        "the second attempt is counted once"
    );

    // The superseded attempt cannot settle the intent; the owning one can.
    assert!(!fx
        .store
        .mark_intent_delivered(row.outbox_id, 1)
        .await
        .expect("the stale outcome write runs"));
    let state: String = fx
        .admin
        .query_one(
            "SELECT delivery_state FROM scheduling_outbox WHERE outbox_id=$1",
            &[&row.outbox_id],
        )
        .await
        .expect("read the intent")
        .get(0);
    assert_eq!(state, "pending", "an obsolete attempt changes nothing");
    assert!(fx
        .store
        .mark_intent_delivered(row.outbox_id, 2)
        .await
        .expect("the owning outcome write runs"));
}

#[tokio::test]
async fn an_expired_dispatch_lease_cannot_start_a_send() {
    let fx = fixture().await;
    let _ = booked(&fx, 90, 200, "expired-dispatch").await;
    let due = Utc::now() + TimeDelta::days(1);
    let rows = fx
        .store
        .claim_due_intents(due, 1, TimeDelta::minutes(10))
        .await
        .expect("claim one intent");
    let row = rows.first().expect("a due intent");
    for (remaining, dispatchable) in [(6, true), (5, false), (0, false), (-1, false)] {
        let now = due + TimeDelta::minutes(10) - TimeDelta::seconds(remaining);
        fx.store.pin_clock(Arc::new(move || now));
        assert_eq!(
            fx.store
                .intent_still_dispatchable(row.outbox_id, row.attempts)
                .await
                .expect("check dispatch eligibility"),
            dispatchable,
            "remaining lease seconds: {remaining}"
        );
    }
}

/// Suppression wins up to the send: a reminder claimed for dispatch whose
/// appointment is then cancelled is skipped, its row is retained as
/// accounting, and the in-flight attempt's outcome cannot land.
#[tokio::test]
async fn a_suppressed_reminder_is_skipped_and_keeps_its_accounting() {
    let fx = fixture().await;
    let (appointment, revision) = booked(&fx, 300, 440, "suppress-1").await;
    let due = Utc::now() + TimeDelta::days(1);
    let claimed: Vec<_> = fx
        .store
        .claim_due_intents(due, 100, TimeDelta::minutes(10))
        .await
        .expect("the delivery sweep runs")
        .into_iter()
        .filter(|intent| intent.purpose == "reminder")
        .collect();
    assert_eq!(claimed.len(), 1);
    let reminder = &claimed[0];

    // The caller cancels while the claimed reminder is in flight.
    let (status, _) = fx
        .post(
            &format!("/v1/appointments/{appointment}/cancel"),
            &fx.agent,
            "suppress-cancel",
            json!({"observedRevision": revision, "reason": null}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // The pre-send check skips the suppressed reminder.
    assert!(
        !fx.store
            .intent_still_dispatchable(reminder.outbox_id, reminder.attempts)
            .await
            .expect("the liveness read runs"),
        "a suppressed reminder is not sent"
    );
    // The in-flight attempt's outcome write cannot land either.
    assert!(!fx
        .store
        .mark_intent_delivered(reminder.outbox_id, reminder.attempts)
        .await
        .expect("the stale outcome write runs"));
    // The row survives as accounting, suppressed rather than deleted.
    let state: String = fx
        .admin
        .query_one(
            "SELECT delivery_state FROM scheduling_outbox WHERE outbox_id=$1",
            &[&reminder.outbox_id],
        )
        .await
        .expect("read the intent")
        .get(0);
    assert_eq!(state, "suppressed");

    // The cancellation the caller made is still live for its own dispatch:
    // suppression takes reminders, not the audit trail of the change.
    let cancellation: Uuid = fx
        .admin
        .query_one(
            "SELECT outbox_id FROM scheduling_outbox WHERE claim_id=$1 AND purpose='cancellation'",
            &[&Uuid::parse_str(&appointment).expect("a claim identifier")],
        )
        .await
        .expect("the cancellation intent is minted")
        .get(0);
    fx.store
        .claim_due_intents(due, 100, TimeDelta::minutes(10))
        .await
        .expect("lease the cancellation before dispatch");
    assert!(
        fx.store
            .intent_still_dispatchable(cancellation, 1)
            .await
            .expect("the liveness read runs"),
        "the cancellation intent stays dispatchable"
    );
}

/// An arrival-window offering explains its own start: the probe carries the
/// window's current revision, so a free start explains as admitting and a
/// full one as the public capacity refusal, never as a revision mismatch.
#[tokio::test]
async fn explain_answers_a_window_offering_rather_than_a_revision_mismatch() {
    let start = (Utc::now() + TimeDelta::hours(3))
        .with_nanosecond(0)
        .expect("second precision");
    let fx = fixture_with_window(start).await;
    let uri = format!(
        "/v1/availability/explain?offering={WINDOW_OFFERING}&start={}",
        stamp(start)
    );
    let (status, free) = fx.get(&uri, &fx.agent).await;
    assert_eq!(status, StatusCode::OK, "{free}");
    assert!(
        free["publicCode"].is_null(),
        "a free window start explains as admitting: {free}"
    );

    // Fill both published units; the same probe now explains the refusal a
    // booking would receive.
    for (key, channel) in [
        ("explain-a", Some("assisted")),
        ("explain-b", Some("public")),
    ] {
        let (status, booked_body) = fx
            .post(
                "/v1/appointments",
                &fx.agent,
                key,
                arrival(&fx, start, channel),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{booked_body}");
    }
    let (status, full) = fx.get(&uri, &fx.agent).await;
    assert_eq!(status, StatusCode::OK, "{full}");
    assert_eq!(full["publicCode"], "capacity.exhausted", "{full}");
}

/// A default availability request, with neither start nor end, mints a
/// cursor its own continuation can use: the effective interval rides with
/// the cursor instead of being re-derived from the next request's now.
#[tokio::test]
async fn a_default_availability_request_continues_its_own_cursor() {
    let fx = fixture().await;
    let (status, first) = fx
        .get(
            &format!("/v1/availability?offering={OFFERING}&limit=2"),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let cursor = first["nextCursor"]
        .as_str()
        .expect("a limited availability page carries a cursor")
        .to_owned();
    let first_last = moment(&first["items"][0], "start");

    // The continuation omits start and end exactly as the first page did.
    let (status, second) = fx
        .get(
            &format!("/v1/availability?offering={OFFERING}&limit=2&cursor={cursor}"),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert!(!second["items"]
        .as_array()
        .expect("a page of items")
        .is_empty());
    let second_first = moment(&second["items"][0], "start");
    assert!(
        second_first > first_last,
        "the continuation resumes after the first page"
    );

    // A caller that narrows the range on continuation is asking a different
    // listing, and the cursor refuses it.
    let (status, _) = fx
        .get(
            &format!(
                "/v1/availability?offering={OFFERING}&limit=2&start={}&cursor={cursor}",
                stamp(Utc::now() + TimeDelta::minutes(90))
            ),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Explicit bounds continue as they always did: the same interval twice
    // is the same listing.
    let (status, bounded) = fx
        .get(
            &format!("{}&limit=2", availability_uri(OFFERING, 90, 620)),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{bounded}");
    let bounded_cursor = bounded["nextCursor"]
        .as_str()
        .expect("a bounded window under a page limit pages");
    let (status, _) = fx
        .get(
            &format!("/v1/availability?offering={OFFERING}&limit=2&cursor={bounded_cursor}"),
            &fx.agent,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// A reschedule suppresses the reminder its obsolete revision minted and
/// mints the replacement at the new revision: the obsolete row is retained
/// as accounting, the replacement stays live for dispatch, and a reminder
/// that names anything but the appointment's current revision is never
/// sent, whether a swap marked it or not.
#[tokio::test]
async fn a_reschedule_suppresses_the_obsolete_reminder_and_mints_its_replacement() {
    let fx = fixture().await;
    let (appointment, revision) = booked(&fx, 300, 440, "reschedule-remind").await;
    let due = Utc::now() + TimeDelta::days(1);
    let claimed: Vec<_> = fx
        .store
        .claim_due_intents(due, 100, TimeDelta::minutes(10))
        .await
        .expect("the delivery sweep runs")
        .into_iter()
        .filter(|intent| intent.purpose == "reminder")
        .collect();
    assert_eq!(
        claimed.len(),
        1,
        "the booking minted one reminder at revision 1"
    );
    let obsolete = &claimed[0];

    // The caller moves the appointment clear of the old slot.
    let later = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment}/reschedule"),
            &fx.agent,
            "reschedule-remind-move",
            json!({
                "observedRevision": revision,
                "admission": admission(&fx, OFFERING, later),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["revision"], 2, "the move wrote the next revision");

    let claim_id = Uuid::parse_str(&appointment).expect("a claim identifier");
    let rows = fx
        .admin
        .query(
            "SELECT outbox_id, appointment_revision, delivery_state FROM scheduling_outbox \
             WHERE claim_id=$1 AND purpose='reminder' ORDER BY created_at",
            &[&claim_id],
        )
        .await
        .expect("read the appointment's reminders");
    assert_eq!(
        rows.len(),
        2,
        "the obsolete reminder is retained beside its replacement"
    );
    let obsolete_state: String = rows[0].get(2);
    assert_eq!(
        obsolete_state, "suppressed",
        "the claimed reminder is suppressed, not deleted"
    );
    let replacement: Uuid = rows[1].get(0);
    assert_eq!(
        rows[1].get::<_, i64>(1),
        2,
        "the replacement names the new revision"
    );
    assert_eq!(
        rows[1].get::<_, String>(2),
        "pending",
        "the replacement is live for dispatch"
    );

    fx.store
        .claim_due_intents(due, 100, TimeDelta::minutes(10))
        .await
        .expect("lease the replacement before dispatch");
    // The obsolete reminder is skipped, and the replacement is live.
    assert!(!fx
        .store
        .intent_still_dispatchable(obsolete.outbox_id, obsolete.attempts)
        .await
        .expect("the liveness read runs"));
    assert!(fx
        .store
        .intent_still_dispatchable(replacement, 1)
        .await
        .expect("the liveness read runs"));

    // The revision clause decides on its own: a pending reminder that names
    // an appointment revision other than the current one is not sent, even
    // when nothing marked the row.
    fx.admin
        .execute(
            "UPDATE scheduling_outbox SET appointment_revision=1 WHERE outbox_id=$1",
            &[&replacement],
        )
        .await
        .expect("age the replacement's revision");
    assert!(
        !fx.store
            .intent_still_dispatchable(replacement, 1)
            .await
            .expect("the liveness read runs"),
        "a reminder naming an obsolete revision is not sent"
    );
}
