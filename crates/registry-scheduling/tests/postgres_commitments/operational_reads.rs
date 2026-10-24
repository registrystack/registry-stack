// SPDX-License-Identifier: Apache-2.0

use super::*;

fn operator(subject: &str) -> String {
    operational_token(
        subject,
        "scheduling-read scheduling-appointments-desk scheduling-appointments-supervisor",
    )
}

fn operational_uri(start: DateTime<Utc>, end: DateTime<Utc>, profile: &str) -> String {
    format!(
        "/v1/operational/appointments?service=registry-update&location=north-counter&start={}&end={}&timeBasis=displayed&profile={profile}",
        stamp(start),
        stamp(end),
    )
}

#[tokio::test]
async fn operational_pages_require_one_profile_and_bind_every_authority_dimension() {
    let fx = fixture().await;
    let first = first_slot(&fx, OFFERING, 300, 500).await;
    let mut first_admission = admission(&fx, OFFERING, first);
    first_admission["externalReferences"] = json!([
        case_reference("case-operational"),
        {"product": "other-product", "recordType": "record", "identifier": "hidden"}
    ]);
    let (status, first_body) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "operational-first",
            json!({"hold": null, "admission": first_admission}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{first_body}");
    let second = first_slot(&fx, OFFERING, 520, 700).await;
    let (status, second_body) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "operational-second",
            json!({"hold": null, "admission": admission(&fx, OFFERING, second)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{second_body}");
    begin_current_test_writer(&fx.admin).await;
    fx.admin
        .execute(
            "UPDATE scheduling_claims SET recipient_count=NULL, attendee_count=NULL WHERE claim_id=$1",
            &[&Uuid::parse_str(second_body["appointmentId"].as_str().unwrap()).unwrap()],
        )
        .await
        .expect("simulate a legacy appointment without retained counts");
    commit_current_test_writer(&fx.admin).await;
    let uri = format!(
        "{}&limit=1",
        operational_uri(pinned_now(), pinned_now() + TimeDelta::days(2), "desk")
    );
    for token in [&fx.reader, &fx.agent] {
        let (status, refusal) = fx.get(&uri, token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
        assert_eq!(refusal["code"], "profile.not-authorized");
    }

    let credential = operator("operations-one");
    let (status, ambiguous) = fx.get(&uri.replace("&profile=desk", ""), &credential).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{ambiguous}");
    assert_eq!(ambiguous["code"], "profile.not-authorized");
    let (status, first_page) = fx.get(&uri, &credential).await;
    assert_eq!(status, StatusCode::OK, "{first_page}");
    let item = &first_page["items"][0];
    assert_eq!(item["service"], "registry-update");
    assert_eq!(item["location"], "north-counter");
    assert_eq!(item["resource"], "station-1");
    assert_eq!(item["units"], 1);
    assert_eq!(item["party"], json!({"recipients": 1, "attendees": 1}));
    assert_eq!(
        item["externalReferences"],
        json!([case_reference("case-operational")])
    );
    for forbidden in [
        "actor",
        "channel",
        "ownerIssuer",
        "ownerSubject",
        "policyRevision",
        "createdAt",
        "cancelledAt",
    ] {
        assert!(item.get(forbidden).is_none(), "{forbidden} leaked: {item}");
    }
    let cursor = first_page["nextCursor"].as_str().expect("a second page");
    let continuation = format!("{uri}&cursor={cursor}");
    assert_eq!(fx.get(&continuation, &credential).await.0, StatusCode::OK);
    let (status, complete) = fx
        .get(
            &operational_uri(pinned_now(), pinned_now() + TimeDelta::days(2), "desk"),
            &credential,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{complete}");
    let legacy = complete["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["appointmentId"] == second_body["appointmentId"])
        .expect("legacy appointment remains in the authorized work list");
    assert!(legacy.get("party").is_none(), "{legacy}");

    let other_caller = operator("operations-two");
    assert_eq!(
        fx.get(&continuation, &other_caller).await.0,
        StatusCode::BAD_REQUEST,
        "a cursor is bound to verified issuer, subject and client"
    );
    assert_eq!(
        fx.get(
            &continuation.replace("profile=desk", "profile=supervisor"),
            &credential,
        )
        .await
        .0,
        StatusCode::BAD_REQUEST,
        "a cursor is bound to one exact profile and digest"
    );
    assert_eq!(
        fx.get(
            &format!(
                "{}&resource=station-1&cursor={cursor}",
                operational_uri(pinned_now(), pinned_now() + TimeDelta::days(2), "desk")
            ),
            &credential,
        )
        .await
        .0,
        StatusCode::BAD_REQUEST,
        "a narrower resource filter is a different listing"
    );
    let reference_uri = format!(
        "{}&externalReferenceProduct=registry-casework&externalReferenceRecordType=case&externalReferenceIdentifier=case-operational",
        operational_uri(
            pinned_now(),
            pinned_now() + TimeDelta::days(2),
            "desk"
        )
    );
    let (status, referenced) = fx.get(&reference_uri, &credential).await;
    assert_eq!(status, StatusCode::OK, "{referenced}");
    assert_eq!(referenced["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        referenced["items"][0]["appointmentId"],
        item["appointmentId"]
    );
    let (status, partial) = fx
        .get(
            &format!("{uri}&externalReferenceProduct=registry-casework"),
            &credential,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{partial}");

    let appointment_id = item["appointmentId"].as_str().unwrap();
    let (status, refusal) = fx
        .get(
            &format!("/v1/appointments/{appointment_id}/history"),
            &credential,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    assert_eq!(refusal["code"], "operation.not-authorized");
}

#[tokio::test]
async fn a_later_offering_move_does_not_relabel_a_closed_appointment() {
    let fx = fixture().await;
    let (appointment_id, revision) = booked(&fx, 500, 700, "operational-old-revision").await;
    let (status, cancelled) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/cancel"),
            &fx.agent,
            "operational-old-revision-cancel",
            json!({"observedRevision": revision, "reason": "test"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");

    let mut moved = read_policy(POLICY).unwrap();
    moved
        .offerings
        .iter_mut()
        .find(|offering| offering.id == OFFERING)
        .unwrap()
        .service = "registry-review".to_owned();
    fx.store
        .apply_policy(
            SCHEDULING_ID,
            &moved.policy_digest(),
            &["north-counter".to_owned(), "two-counter".to_owned()],
            &moved,
        )
        .await
        .unwrap();

    let row = fx
        .admin
        .query_one(
            "SELECT operational_service, operational_location FROM scheduling_claims WHERE claim_id=$1",
            &[&Uuid::parse_str(&appointment_id).unwrap()],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "registry-update");
    assert_eq!(row.get::<_, String>(1), "north-counter");
    let uri = format!(
        "{}&state=cancelled",
        operational_uri(pinned_now(), pinned_now() + TimeDelta::days(2), "desk")
    );
    let (status, page) = fx.get(&uri, &operator("operations-history")).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["items"][0]["appointmentId"], appointment_id);
}

pub(super) fn arrival_operational_authority(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    restricted: bool,
) -> registry_scheduling::operational::AuthorizedOperationalRead {
    use registry_scheduling::operational::{
        authorize_operational_read, OperationalIdentity, OperationalReadFilter,
        OperationalTimeBasis,
    };
    let profile = OperationalReadProfileConfig {
        scope: "arrival-operations".into(),
        maximum_past_days: 1,
        maximum_future_days: 90,
        maximum_span_days: 62,
        permissions: vec![OperationalReadPermissionConfig {
            service: "registry-update".into(),
            location: "north-counter".into(),
            resources: if restricted {
                OperationalResourceScope::Exact {
                    ids: vec!["station-1".into()],
                }
            } else {
                OperationalResourceScope::Unrestricted {}
            },
        }],
        projection: OperationalProjectionConfig {
            fields: vec![
                OperationalProjectionField::OccupiedInterval,
                OperationalProjectionField::Allocations,
            ],
            external_reference_products: Vec::new(),
        },
    };
    authorize_operational_read(
        &BTreeMap::from([("arrivals".into(), profile)]),
        &["arrival-operations".into()],
        Some("arrivals"),
        OperationalIdentity::new(ISSUER.into(), "desk".into(), CLIENT.into()).unwrap(),
        OperationalReadFilter::new(
            "registry-update".into(),
            "north-counter".into(),
            None,
            OperationalTimeBasis::Occupied,
            start,
            end,
        )
        .unwrap(),
        pinned_now(),
    )
    .unwrap()
}

#[tokio::test]
async fn occupied_worklists_include_arrival_creation_and_confirmation_without_resource_authority_expansion(
) {
    let start = window_start();
    let fx = fixture_with_window(start).await;
    let (status, direct) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-ops-direct",
            arrival(&fx, start, Some("public")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{direct}");
    let body = arrival(&fx, start, Some("assisted"))["admission"].clone();
    let (status, hold) = fx
        .post("/v1/holds", &fx.agent, "arrival-ops-hold", body)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    let (status, confirmed) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-ops-confirm",
            json!({"hold": hold["holdId"]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{confirmed}");
    let authority = arrival_operational_authority(start, start + TimeDelta::hours(2), false);
    let page = fx
        .store
        .list_operational_appointments(&authority, None, 1)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].position_start, start);
    let next = fx
        .store
        .list_operational_appointments(
            &authority,
            Some((page[0].position_start, page[0].appointment_id)),
            1,
        )
        .await
        .unwrap();
    assert_eq!(next.len(), 1);
    assert_ne!(page[0].appointment_id, next[0].appointment_id);
    let restricted = arrival_operational_authority(start, start + TimeDelta::hours(2), true);
    assert!(fx
        .store
        .list_operational_appointments(&restricted, None, 10)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn occupied_arrival_reads_ignore_stale_migrated_allocation_intervals_and_projections() {
    let start = window_start();
    let fx = fixture_with_window(start).await;
    let (status, booking) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "arrival-migrated",
            arrival(&fx, start, Some("public")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{booking}");
    let id = Uuid::parse_str(booking["appointmentId"].as_str().unwrap()).unwrap();
    begin_current_test_writer(&fx.admin).await;
    fx.admin.execute("INSERT INTO scheduling_claim_allocations( \
        claim_id,requirement_kind,requirement_index,part_index,offering, \
        operational_service,operational_location,operational_mode,anchor_id,resource_id,occupied_start,occupied_end,units) \
        SELECT claim_id,'primary',0,0,offering,operational_service,operational_location,operational_mode, \
        supply_id,supply_id,occupied_start+interval '1 day',occupied_end+interval '1 day',units \
        FROM scheduling_claims WHERE claim_id=$1", &[&id]).await.unwrap();
    commit_current_test_writer(&fx.admin).await;
    let authority = arrival_operational_authority(start, start + TimeDelta::hours(2), false);
    let page = fx
        .store
        .list_operational_appointments(&authority, None, 10)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].position_start, start);
    assert!(page[0].allocations.as_ref().unwrap().is_empty());
    let old = arrival_operational_authority(
        start + TimeDelta::days(1),
        start + TimeDelta::days(1) + TimeDelta::hours(2),
        false,
    );
    assert!(fx
        .store
        .list_operational_appointments(&old, None, 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        fx.store.resource_supply_impacts().await.unwrap().total,
        0,
        "window identifiers are not missing physical resources"
    );
}
