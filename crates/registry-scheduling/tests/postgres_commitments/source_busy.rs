// SPDX-License-Identifier: Apache-2.0

use super::*;

const BUSY_SCOPE: &str = "scheduling-busy-write";

pub(super) fn profiles() -> BTreeMap<String, BusyImportProfileConfig> {
    let profile = |source_id: &str| BusyImportProfileConfig {
        scope: BUSY_SCOPE.to_owned(),
        source_id: source_id.to_owned(),
        resources: vec!["station-1".to_owned()],
        maximum_past_days: 2,
        maximum_future_days: 60,
        maximum_span_days: 7,
        maximum_freshness_minutes: 120,
        impact_projection: BusyImpactProjection::CountOnly,
    };
    BTreeMap::from([
        ("calendar-a".to_owned(), profile("calendar-a")),
        ("calendar-b".to_owned(), profile("calendar-b")),
    ])
}

pub(super) fn source_router(
    fx: &Fixture,
    profiles: &BTreeMap<String, BusyImportProfileConfig>,
) -> Router {
    let policy = read_policy(POLICY).expect("the source-busy test policy");
    let digest = policy.policy_digest();
    let store = fx.store.clone().with_busy_source_profiles(profiles);
    let keying = AuditHashSecret::new(vec![0x42; 32]).expect("the test audit hash secret");
    let service = Arc::new(
        SchedulingService::new(
            store.clone(),
            policy,
            SCHEDULING_ID.to_owned(),
            i64::try_from(fx.revision).expect("the revision fits i64"),
            digest,
            AuditKeyHasher::Keyed(keying),
            fx.audit.clone(),
            7,
        )
        .with_hooks(fx.hooks.clone()),
    );
    router(HttpState {
        service,
        authenticator: Arc::new(authenticator_with_busy_profiles(profiles.clone())),
    })
}

pub(super) fn reconciliation(
    expected_revision: u64,
    status: &str,
    start: DateTime<Utc>,
    records: Value,
) -> Value {
    let now = pinned_now();
    json!({
        "expectedRevision": expected_revision,
        "observedAt": stamp(now),
        "freshUntil": if status == "fresh" {
            Value::String(stamp(now + TimeDelta::minutes(60)))
        } else {
            Value::Null
        },
        "coverage": {
            "start": stamp(start - TimeDelta::hours(1)),
            "end": stamp(start + TimeDelta::hours(4)),
            "resources": ["station-1"]
        },
        "status": status,
        "records": records
    })
}

async fn apply(http: &Router, token: &str, profile: &str, body: Value) -> (StatusCode, Value) {
    send(
        http.clone(),
        "POST".to_owned(),
        format!("/v1/source-busy/apply?profile={profile}"),
        token.to_owned(),
        None,
        Some(body),
    )
    .await
}

#[tokio::test]
async fn source_owned_reconciliation_is_cas_bounded_private_and_capacity_effective() {
    let fx = fixture().await;
    let first = first_slot(&fx, OFFERING, 300, 700).await;
    let second = first + TimeDelta::minutes(60);
    let (status, booked) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "before-source-busy",
            json!({"admission": admission(&fx, OFFERING, first)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{booked}");

    let profiles = profiles();
    let http = source_router(&fx, &profiles);
    let source_token = operational_token("calendar-importer", BUSY_SCOPE);
    let external_a = "private-external-uid-a";
    let request_a = reconciliation(
        0,
        "fresh",
        first,
        json!([
            {
                "externalUid": external_a,
                "externalRevision": "sequence:1",
                "resource": "station-1",
                "start": stamp(first),
                "end": stamp(first + TimeDelta::minutes(30))
            },
            {
                "externalUid": "private-external-uid-a-2",
                "externalRevision": "sequence:1",
                "resource": "station-1",
                "start": stamp(second),
                "end": stamp(second + TimeDelta::minutes(30))
            }
        ]),
    );
    let (status, preview) = send(
        http.clone(),
        "POST".to_owned(),
        "/v1/source-busy/preview?profile=calendar-a".to_owned(),
        source_token.clone(),
        None,
        Some(request_a.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["currentRevision"], 0);
    assert_eq!(preview["added"], 2);
    assert_eq!(preview["impacts"]["total"], 1);
    let audit_before = fx.capture.entries().len();
    let (status, applied_a) = apply(&http, &source_token, "calendar-a", request_a.clone()).await;
    assert_eq!(status, StatusCode::OK, "{applied_a}");
    assert_eq!(applied_a["kind"], "applied");
    assert_eq!(applied_a["revision"], 1);
    assert_eq!(applied_a["impacts"]["total"], 1);
    assert_eq!(applied_a["impacts"]["detailsAvailable"], false);
    assert_eq!(applied_a["impacts"]["truncated"], true);
    assert!(applied_a["impacts"].get("items").is_none());

    let audit = serde_json::to_string(&fx.capture.entries().split_off(audit_before)).unwrap();
    assert!(!audit.contains(external_a));
    assert!(!audit.contains(booked["appointmentId"].as_str().unwrap()));

    let (status, replay) = apply(&http, &source_token, "calendar-a", request_a.clone()).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["kind"], "already-applied");
    assert_eq!(replay["requestDigest"], applied_a["requestDigest"]);

    let mut mismatched = request_a;
    mismatched["records"][0]["externalRevision"] = json!("sequence:2");
    let (status, problem) = apply(&http, &source_token, "calendar-a", mismatched).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{problem}");

    let request_b = reconciliation(
        0,
        "fresh",
        first,
        json!([{
            "externalUid": "private-external-uid-b",
            "externalRevision": "sequence:4",
            "resource": "station-1",
            "start": stamp(second),
            "end": stamp(second + TimeDelta::minutes(30))
        }]),
    );
    let (status, applied_b) = apply(&http, &source_token, "calendar-b", request_b).await;
    assert_eq!(status, StatusCode::OK, "{applied_b}");

    let (status, refusal) = send(
        http.clone(),
        "POST".to_owned(),
        "/v1/appointments".to_owned(),
        fx.agent.clone(),
        Some("blocked-by-source-busy".to_owned()),
        Some(json!({"admission": admission(&fx, OFFERING, second)})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");

    let mut outage = reconciliation(1, "unavailable", first, json!([]));
    outage["observedAt"] = json!(stamp(pinned_now() + TimeDelta::seconds(1)));
    let (status, unavailable) = apply(&http, &source_token, "calendar-a", outage).await;
    assert_eq!(status, StatusCode::OK, "{unavailable}");
    assert_eq!(unavailable["deleted"], 0);

    let mut recovered_empty = reconciliation(2, "fresh", first, json!([]));
    recovered_empty["observedAt"] = json!(stamp(pinned_now() + TimeDelta::seconds(2)));
    let (status, recovered) = apply(&http, &source_token, "calendar-a", recovered_empty).await;
    assert_eq!(status, StatusCode::OK, "{recovered}");
    assert_eq!(recovered["deleted"], 2);
    let rows = fx
        .admin
        .query(
            "SELECT source_id,count(*)::bigint FROM scheduling_busy_intervals GROUP BY source_id ORDER BY source_id",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, String>(0), "calendar-b");
    assert_eq!(rows[0].get::<_, i64>(1), 1);
}

#[tokio::test]
async fn older_observation_at_the_current_revision_cannot_replace_newer_busy_state() {
    let fx = fixture().await;
    let first = first_slot(&fx, OFFERING, 300, 700).await;
    let profiles = profiles();
    let http = source_router(&fx, &profiles);
    let source_token = operational_token("calendar-importer", BUSY_SCOPE);

    let newer = reconciliation(
        0,
        "fresh",
        first,
        json!([{
            "externalUid": "newer-observation",
            "externalRevision": "sequence:2",
            "resource": "station-1",
            "start": stamp(first),
            "end": stamp(first + TimeDelta::minutes(30))
        }]),
    );
    let (status, applied) = apply(&http, &source_token, "calendar-a", newer).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["revision"], 1);

    let older_observed_at = pinned_now() - TimeDelta::minutes(30);
    let mut older_empty = reconciliation(1, "fresh", first, json!([]));
    older_empty["observedAt"] = json!(stamp(older_observed_at));
    older_empty["freshUntil"] = json!(stamp(older_observed_at + TimeDelta::minutes(60)));
    let (status, refusal) = apply(&http, &source_token, "calendar-a", older_empty).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{refusal}");

    let row = fx
        .admin
        .query_one(
            "SELECT h.revision,c.observed_at,count(b.external_uid)::bigint \
             FROM scheduling_busy_source_heads h \
             JOIN scheduling_busy_source_coverage c ON c.source_id=h.source_id \
             LEFT JOIN scheduling_busy_intervals b ON b.source_id=h.source_id \
             WHERE h.source_id='calendar-a' GROUP BY h.revision,c.observed_at",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, DateTime<Utc>>(1), pinned_now());
    assert_eq!(row.get::<_, i64>(2), 1);

    let (status, blocked) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "still-blocked-by-newer-source-busy",
            json!({"admission": admission(&fx, OFFERING, first)}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{blocked}");
}

#[tokio::test]
async fn equal_observation_cannot_replace_overlapping_busy_state() {
    let fx = fixture().await;
    let first = first_slot(&fx, OFFERING, 300, 700).await;
    let profiles = profiles();
    let http = source_router(&fx, &profiles);
    let source_token = operational_token("calendar-importer", BUSY_SCOPE);

    let first_snapshot = reconciliation(
        0,
        "fresh",
        first,
        json!([{
            "externalUid": "equal-observation",
            "externalRevision": "sequence:1",
            "resource": "station-1",
            "start": stamp(first),
            "end": stamp(first + TimeDelta::minutes(30))
        }]),
    );
    let (status, applied) = apply(&http, &source_token, "calendar-a", first_snapshot).await;
    assert_eq!(status, StatusCode::OK, "{applied}");

    let conflicting_empty = reconciliation(1, "fresh", first, json!([]));
    let (status, refusal) = apply(&http, &source_token, "calendar-a", conflicting_empty).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{refusal}");

    let row = fx
        .admin
        .query_one(
            "SELECT h.revision,count(b.external_uid)::bigint \
             FROM scheduling_busy_source_heads h \
             LEFT JOIN scheduling_busy_intervals b ON b.source_id=h.source_id \
             WHERE h.source_id='calendar-a' GROUP BY h.revision",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
}

#[tokio::test]
async fn exact_digest_replay_returns_the_original_bounded_outcome() {
    let fx = fixture().await;
    let first = first_slot(&fx, OFFERING, 300, 700).await;
    let (status, booked) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "source-busy-replay-impact",
            json!({"admission": admission(&fx, OFFERING, first)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{booked}");

    let profiles = profiles();
    let http = source_router(&fx, &profiles);
    let source_token = operational_token("calendar-importer", BUSY_SCOPE);
    let request = reconciliation(
        0,
        "fresh",
        first,
        json!([
            {
                "externalUid": "replay-outcome-a",
                "externalRevision": "sequence:1",
                "resource": "station-1",
                "start": stamp(first),
                "end": stamp(first + TimeDelta::minutes(30))
            },
            {
                "externalUid": "replay-outcome-b",
                "externalRevision": "sequence:1",
                "resource": "station-1",
                "start": stamp(first + TimeDelta::minutes(60)),
                "end": stamp(first + TimeDelta::minutes(90))
            }
        ]),
    );
    let (status, applied) = apply(&http, &source_token, "calendar-a", request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["added"], 2);
    assert_eq!(applied["impacts"]["total"], 1);

    let appointment_id = booked["appointmentId"].as_str().unwrap();
    let (status, cancelled) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/cancel"),
            &fx.agent,
            "source-busy-replay-cancel",
            json!({"observedRevision": booked["revision"], "reason": null}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");

    let (status, replay) = apply(&http, &source_token, "calendar-a", request).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["kind"], "already-applied");
    assert_eq!(replay["revision"], applied["revision"]);
    assert_eq!(replay["requestDigest"], applied["requestDigest"]);
    assert_eq!(replay["added"], applied["added"]);
    assert_eq!(replay["changed"], applied["changed"]);
    assert_eq!(replay["deleted"], applied["deleted"]);
    assert_eq!(
        replay["retainedOutsideAuthority"],
        applied["retainedOutsideAuthority"]
    );
    assert_eq!(
        replay["retainedAcrossCoverageBoundary"],
        applied["retainedAcrossCoverageBoundary"]
    );
    assert_eq!(replay["impacts"], applied["impacts"]);
}

#[tokio::test]
async fn exact_digest_replay_without_the_original_outcome_is_unresolved() {
    let fx = fixture().await;
    let first = first_slot(&fx, OFFERING, 300, 700).await;
    let profiles = profiles();
    let http = source_router(&fx, &profiles);
    let source_token = operational_token("calendar-importer", BUSY_SCOPE);
    let request = reconciliation(
        0,
        "fresh",
        first,
        json!([{
            "externalUid": "legacy-outcome",
            "externalRevision": "sequence:1",
            "resource": "station-1",
            "start": stamp(first),
            "end": stamp(first + TimeDelta::minutes(30))
        }]),
    );
    let (status, applied) = apply(&http, &source_token, "calendar-a", request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    fx.admin
        .execute(
            "UPDATE scheduling_busy_source_heads SET last_outcome=NULL WHERE source_id='calendar-a'",
            &[],
        )
        .await
        .unwrap();

    let (status, unresolved) = apply(&http, &source_token, "calendar-a", request).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{unresolved}");
    assert_eq!(unresolved["code"], "service.unavailable");

    let row = fx
        .admin
        .query_one(
            "SELECT h.revision,count(b.external_uid)::bigint \
             FROM scheduling_busy_source_heads h \
             LEFT JOIN scheduling_busy_intervals b ON b.source_id=h.source_id \
             WHERE h.source_id='calendar-a' GROUP BY h.revision",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
}

#[tokio::test]
async fn source_busy_impacts_include_window_room_reservations() {
    use super::multi_window::{room, session, session_start, sessions_fixture, FIRST_WINDOW};

    let mut first = session(FIRST_WINDOW, 1, session_start(2), 2);
    first.resources = room();
    let fx = sessions_fixture(vec![first.clone()]).await;
    let profiles = profiles();
    let http = source_router(&fx, &profiles);
    let credential = operational_token("source-operator", BUSY_SCOPE);
    let request = reconciliation(
        0,
        "fresh",
        first.start,
        json!([{
            "externalUid": "synthetic-busy-event", "externalRevision": "1", "resource": "station-1",
            "start": stamp(first.start), "end": stamp(first.end)
        }]),
    );
    let (status, preview) = send(
        http,
        "POST".into(),
        "/v1/source-busy/preview?profile=calendar-a".into(),
        credential,
        None,
        Some(request),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["impacts"]["total"], 1, "{preview}");
}

#[tokio::test]
async fn zero_stock_member_with_missing_source_coverage_does_not_block_a_positive_alternative() {
    let fx = fixture().await;
    let start = first_slot(&fx, OFFERING, 300, 700).await;
    let (mut facts, _) = fx.store.facts().await.unwrap();
    let pool = facts
        .pools
        .iter_mut()
        .find(|p| p.id == "north-counter")
        .unwrap();
    let mut alternative = pool.members[0].clone();
    alternative.resource_id = "station-alternative".into();
    pool.members[0].capacity_units = 0;
    pool.members.push(alternative);
    fx.store.replace_facts(SCHEDULING_ID, &facts).await.unwrap();
    let profiles = profiles();
    let http = source_router(&fx, &profiles);
    let (status, result) = send(
        http,
        "POST".into(),
        "/v1/appointments".into(),
        fx.agent.clone(),
        Some("positive-alternative".into()),
        Some(json!({"admission": admission(&fx, OFFERING, start)})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
}
