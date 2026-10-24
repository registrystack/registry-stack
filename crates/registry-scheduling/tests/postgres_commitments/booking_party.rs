// SPDX-License-Identifier: Apache-2.0

use super::*;

fn organization_reference(identifier: &str) -> Value {
    json!({
        "role": "organization",
        "reference": {
            "product": "request-source",
            "recordType": "organization",
            "identifier": identifier,
        }
    })
}

fn manager_grant(manager: &str, create_for: bool) -> Value {
    let mut grant = grant_claims();
    grant["identity"]["schedulingManager"] = json!(manager);
    if create_for {
        let actions = grant["registry_grant_bounds"]["permissions"][0]["actions"]
            .as_array_mut()
            .expect("scheduling actions");
        actions.push(json!("hold.create-for"));
        actions.push(json!("appointment.create-for"));
        actions.push(json!("appointment.read"));
    }
    grant
}

fn manager_token(manager: &str, create_for: bool) -> String {
    let mut claims = json!({
        "sub": "assisted-actor",
        "azp": CLIENT,
        "registry_scopes": "scheduling-read scheduling-explain",
        "registry_actor_kind": "service",
    });
    claims.as_object_mut().expect("claims object").extend(
        manager_grant(manager, create_for)
            .as_object()
            .expect("grant object")
            .clone(),
    );
    token(claims)
}

fn manager_detail_token(manager: &str) -> String {
    let mut claims = json!({
        "sub": "assisted-actor",
        "azp": CLIENT,
        "registry_scopes": "scheduling-explain",
        "registry_actor_kind": "service",
    });
    claims.as_object_mut().expect("claims object").extend(
        manager_grant(manager, true)
            .as_object()
            .expect("grant object")
            .clone(),
    );
    token(claims)
}

fn manager_status_grant(manager: &str, create_for: bool) -> Value {
    let grant = manager_grant(manager, create_for);
    json!({
        "grantId": grant["registry_grant_id"],
        "sourceIssuer": grant["registry_grant_source_issuer"],
        "principal": "assisted-actor",
        "client": grant["registry_grant_client"],
        "resource": grant["registry_grant_resource"],
        "purpose": grant["registry_purpose"],
        "bounds": grant["registry_grant_bounds"],
        "subjects": grant["identity"],
        "expiresAt": grant["registry_grant_exp"],
    })
}

#[tokio::test]
async fn an_assisted_manager_is_selected_only_from_fresh_exact_source_authority() {
    let manager = "case-17-scheduling-manager";
    let offline = fixture().await;
    let offline_start = first_slot(&offline, OFFERING, 300, 440).await;
    let mut offline_request = admission(&offline, OFFERING, offline_start);
    offline_request["manager"] = json!("schedulingManager");
    let (status, refusal) = offline
        .post(
            "/v1/appointments",
            &manager_token(manager, true),
            "managed-offline-refused",
            json!({"hold": null, "admission": offline_request}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");

    let response = ResponseTemplate::new(200).set_body_json(json!({
        "active": true,
        "grant": manager_status_grant(manager, true),
    }));
    let (_authority, status) = activated_task_status(response).await;
    let fx = fixture_with_task_status(status).await;
    let start = first_slot(&fx, OFFERING, 300, 440).await;
    let mut request = admission(&fx, OFFERING, start);
    request["manager"] = json!("schedulingManager");
    let body = json!({"hold": null, "admission": request});
    let actor = manager_token(manager, true);

    let (created_status, created) = fx
        .post("/v1/appointments", &actor, "managed-create", body.clone())
        .await;
    assert_eq!(created_status, StatusCode::CREATED, "{created}");
    assert_eq!(created["manager"], "schedulingManager");

    let (replay_status, replay) = fx
        .post("/v1/appointments", &actor, "managed-create", body)
        .await;
    assert_eq!(replay_status, StatusCode::CREATED, "{replay}");
    assert_eq!(replay["appointmentId"], created["appointmentId"]);

    let appointment_id = created["appointmentId"].as_str().unwrap();
    let (read_status, read) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &actor)
        .await;
    assert_eq!(read_status, StatusCode::OK, "{read}");
    assert_eq!(read["appointmentId"], created["appointmentId"]);
    let detail_only = manager_detail_token(manager);
    let (status, detail) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &detail_only)
        .await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    for route in [
        "/v1/scheduling".to_owned(),
        appointments_by_reference_uri("manager-detail-only", 10, None),
        format!("/v1/appointments/{appointment_id}/history"),
        format!(
            "/v1/operational/appointments?service=registry-update&location=north-counter&start={}&end={}&timeBasis=displayed&profile=desk",
            stamp(pinned_now()),
            stamp(pinned_now() + TimeDelta::days(1)),
        ),
    ] {
        let (status, refusal) = fx.get(&route, &detail_only).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {refusal}");
        assert_eq!(refusal["code"], "profile.not-authorized", "{route}");
    }
    let (wrong_status, wrong) = fx
        .get(
            &format!("/v1/appointments/{appointment_id}"),
            &manager_token("another-manager", true),
        )
        .await;
    assert_eq!(wrong_status, StatusCode::FORBIDDEN, "{wrong}");
    let (history_status, history) = fx
        .get(
            &format!("/v1/appointments/{appointment_id}/history"),
            &actor,
        )
        .await;
    assert_eq!(history_status, StatusCode::FORBIDDEN, "{history}");

    let row = fx
        .admin
        .query_one(
            "SELECT owner_issuer, owner_subject, manager_source_issuer, manager_subject \
             FROM scheduling_claims WHERE claim_id=$1",
            &[&Uuid::parse_str(appointment_id).unwrap()],
        )
        .await
        .expect("stored source manager");
    assert_eq!(row.get::<_, Option<String>>(0).as_deref(), Some(ISSUER));
    assert_eq!(
        row.get::<_, Option<String>>(1).as_deref(),
        Some("assisted-actor")
    );
    assert_eq!(
        row.get::<_, Option<String>>(2).as_deref(),
        Some("https://authority.test")
    );
    assert_eq!(row.get::<_, Option<String>>(3).as_deref(), Some(manager));

    let hold_start = first_slot(&fx, OFFERING, 500, 660).await;
    let mut held = admission(&fx, OFFERING, hold_start);
    held["manager"] = json!("schedulingManager");
    let (status, hold) = fx.post("/v1/holds", &actor, "managed-hold", held).await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    assert_eq!(hold["manager"], "schedulingManager");
    let (status, confirmed) = fx
        .post(
            "/v1/appointments",
            &actor,
            "managed-confirm",
            json!({"hold": hold["holdId"]}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{confirmed}");
    assert_eq!(confirmed["manager"], "schedulingManager");

    let moved_start = first_slot(&fx, OFFERING, 700, 840).await;
    let reschedule = json!({
        "observedRevision": created["revision"],
        "admission": admission(&fx, OFFERING, moved_start),
    });
    let (status, refusal) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &manager_token("another-manager", true),
            "managed-reschedule-wrong-manager",
            reschedule.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &actor,
            "managed-reschedule",
            reschedule,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["manager"], "schedulingManager");
    let (status, cancelled) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/cancel"),
            &actor,
            "managed-cancel",
            json!({"observedRevision": moved["revision"], "reason": null}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cancelled}");
    assert_eq!(cancelled["manager"], "schedulingManager");

    let release_start = first_slot(&fx, OFFERING, 860, 1000).await;
    let mut releasable = admission(&fx, OFFERING, release_start);
    releasable["manager"] = json!("schedulingManager");
    let (status, releasable_hold) = fx
        .post("/v1/holds", &actor, "managed-releasable-hold", releasable)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{releasable_hold}");
    let release_route = format!("/v1/holds/{}", releasable_hold["holdId"].as_str().unwrap());
    assert_eq!(
        fx.delete(&release_route, &manager_token("another-manager", true))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fx.delete(&release_route, &actor).await.0,
        StatusCode::NO_CONTENT
    );

    let mut ordinary = admission(&fx, OFFERING, start + TimeDelta::minutes(60));
    ordinary["manager"] = json!("schedulingManager");
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &manager_token(manager, false),
            "managed-without-create-for",
            json!({"hold": null, "admission": ordinary}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
}

fn detail_grant(subject_actions: &[&str], location: &str) -> Value {
    let mut grant = grant_claims();
    grant["registry_grant_bounds"]["permissions"] = json!([{
        "service": "registry-update",
        "location": location,
        "actions": subject_actions,
    }]);
    grant
}

fn detail_token(subject: &str, grant: &Value) -> String {
    let mut claims = json!({
        "sub": subject,
        "azp": CLIENT,
        "registry_scopes": "scheduling-explain",
        "registry_actor_kind": "service",
    });
    claims
        .as_object_mut()
        .expect("claims object")
        .extend(grant.as_object().expect("grant object").clone());
    token(claims)
}

fn detail_status_grant(subject: &str, grant: &Value) -> Value {
    json!({
        "grantId": grant["registry_grant_id"],
        "sourceIssuer": grant["registry_grant_source_issuer"],
        "principal": subject,
        "client": grant["registry_grant_client"],
        "resource": grant["registry_grant_resource"],
        "purpose": grant["registry_purpose"],
        "bounds": grant["registry_grant_bounds"],
        "subjects": grant["identity"],
        "expiresAt": grant["registry_grant_exp"],
    })
}

#[tokio::test]
async fn a_current_appointment_read_grant_reads_a_self_booked_appointment_only_within_its_bounds() {
    let desk = "detail-desk";
    let reader_grant = detail_grant(&["appointment.read"], "north-counter");
    let response = ResponseTemplate::new(200).set_body_json(json!({
        "active": true,
        "grant": exact_task_status_grant(),
    }));
    let (authority, status) = activated_task_status(response).await;
    let fx = fixture_with_task_status(status).await;
    let (appointment_id, _) = booked(&fx, 300, 440, "self-booked-detail").await;
    let route = format!("/v1/appointments/{appointment_id}");

    // The status authority now vouches for the desk's grant instead of the
    // owner's.
    authority.reset().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "synthetic-status-service",
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": "casework:grants:status"
        })))
        .mount(&authority)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/v1/task-grants/11111111-1111-4111-8111-111111111111/status",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "grant": detail_status_grant(desk, &reader_grant),
        })))
        .mount(&authority)
        .await;

    // Accepted residual: a current online appointment.read grant for the
    // offering's service and location reads by id although the caller is not
    // the owner.
    let desk_token = detail_token(desk, &reader_grant);
    let (status, detail) = fx.get(&route, &desk_token).await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert_eq!(detail["appointmentId"], appointment_id.as_str());

    // The same subject with a grant bounded to another location is refused.
    let elsewhere = detail_token(desk, &detail_grant(&["appointment.read"], "south-counter"));
    let (status, refusal) = fx.get(&route, &elsewhere).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    assert_eq!(refusal["code"], "operation.not-authorized");

    // The right bounds without the appointment.read action are refused.
    let wrong_action = detail_token(desk, &detail_grant(&["attendance.record"], "north-counter"));
    let (status, refusal) = fx.get(&route, &wrong_action).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    assert_eq!(refusal["code"], "profile.not-authorized");

    // The grant does not widen to the appointment history.
    let (status, refusal) = fx.get(&format!("{route}/history"), &desk_token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    assert_eq!(refusal["code"], "profile.not-authorized");
}

#[tokio::test]
async fn assisted_manager_authority_is_bound_into_idempotency_and_retention() {
    let manager = "case-18-scheduling-manager";
    let response = ResponseTemplate::new(200).set_body_json(json!({
        "active": true,
        "grant": manager_status_grant(manager, true),
    }));
    let (_authority, status) = activated_task_status(response).await;
    let fx = fixture_with_task_status(status).await;
    let start = first_slot(&fx, OFFERING, 300, 440).await;
    let mut managed = admission(&fx, OFFERING, start);
    managed["manager"] = json!("schedulingManager");
    let actor = manager_token(manager, true);
    let (status, created) = fx
        .post(
            "/v1/appointments",
            &actor,
            "manager-hash",
            json!({"hold": null, "admission": managed}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    let mut retained_replay = admission(&fx, OFFERING, start);
    retained_replay["manager"] = json!("schedulingManager");
    let (status, replay) = fx
        .post(
            "/v1/appointments",
            &actor,
            "manager-hash",
            json!({"hold": null, "admission": retained_replay}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{replay}");
    assert_eq!(replay["appointmentId"], created["appointmentId"]);

    let unassisted = admission(&fx, OFFERING, start);
    let (status, collision) = fx
        .post(
            "/v1/appointments",
            &actor,
            "manager-hash",
            json!({"hold": null, "admission": unassisted}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{collision}");
    assert_eq!(collision["code"], "idempotency.key-reused");

    fx.store
        .erase_expired_claim_owners(start + TimeDelta::days(3), 1)
        .await
        .expect("erase retained manager authority");
    let row = fx
        .admin
        .query_one(
            "SELECT owner_issuer, owner_subject, manager_source_issuer, manager_subject \
             FROM scheduling_claims WHERE claim_id=$1",
            &[&Uuid::parse_str(created["appointmentId"].as_str().unwrap()).unwrap()],
        )
        .await
        .expect("erased manager authority");
    for index in 0..4 {
        assert_eq!(row.get::<_, Option<String>>(index), None);
    }

    let mut replay_request = admission(&fx, OFFERING, start);
    replay_request["manager"] = json!("schedulingManager");
    let (status, replay) = fx
        .post(
            "/v1/appointments",
            &actor,
            "manager-hash",
            json!({"hold": null, "admission": replay_request}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{replay}");
    assert_eq!(replay["code"], "operation.not-authorized");
    let (status, hidden) = fx
        .get(
            &format!(
                "/v1/appointments/{}",
                created["appointmentId"].as_str().unwrap()
            ),
            &actor,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{hidden}");
}

#[tokio::test]
async fn declared_party_and_typed_references_survive_hold_confirmation_and_reschedule() {
    let fx = fixture().await;
    let reference = organization_reference("organization-17");
    let held_slot = first_slot(&fx, OFFERING, 300, 440).await;
    let mut held_admission = admission(&fx, OFFERING, held_slot);
    held_admission["party"] = json!({"recipients": 1, "attendees": 3});
    held_admission["partyReferences"] = json!([reference.clone()]);

    let (status, hold) = fx
        .post("/v1/holds", &fx.agent, "party-hold", held_admission)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    assert_eq!(hold["party"], json!({"recipients": 1, "attendees": 3}));
    assert_eq!(hold["partyReferences"], json!([reference.clone()]));

    let (status, confirmed) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "party-confirm",
            json!({"hold": hold["holdId"], "admission": null}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{confirmed}");
    assert_eq!(confirmed["party"], hold["party"]);
    assert_eq!(confirmed["partyReferences"], hold["partyReferences"]);

    let appointment_id = confirmed["appointmentId"]
        .as_str()
        .expect("an appointment identifier");
    let moved_slot = first_slot(&fx, OFFERING, 480, 620).await;
    let mut moved_admission = admission(&fx, OFFERING, moved_slot);
    moved_admission["party"] = json!({"recipients": 1, "attendees": 4});
    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "party-reschedule",
            json!({
                "observedRevision": confirmed["revision"],
                "admission": moved_admission,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["party"], json!({"recipients": 1, "attendees": 4}));
    assert_eq!(moved["partyReferences"], json!([reference.clone()]));

    let row = fx
        .admin
        .query_one(
            "SELECT recipient_count, attendee_count, party_references \
             FROM scheduling_claims WHERE claim_id=$1",
            &[&Uuid::parse_str(appointment_id).expect("appointment UUID")],
        )
        .await
        .expect("stored party facts");
    assert_eq!(row.get::<_, Option<i32>>(0), Some(1));
    assert_eq!(row.get::<_, Option<i32>>(1), Some(4));
    assert_eq!(row.get::<_, Value>(2), json!([reference.clone()]));

    let mut relink = admission(&fx, OFFERING, moved_slot);
    relink["partyReferences"] = json!([organization_reference("organization-18")]);
    let (status, refusal) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "party-relink",
            json!({"observedRevision": moved["revision"], "admission": relink}),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refusal}");
    assert_eq!(refusal["code"], "request.unprocessable");
}

#[tokio::test]
async fn a_resource_reservation_omits_people_only_under_explicit_exact_time_policy() {
    let policy = POLICY.replacen(
        "durationMinutes: 30\n      bufferBeforeMinutes: 0",
        "durationMinutes: 30\n      partyCounts: optional\n      bufferBeforeMinutes: 0",
        1,
    );
    let fx = fixture_publishing(
        &policy,
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await;
    let (status, catalogue) = fx.get("/v1/offerings", &fx.reader).await;
    assert_eq!(status, StatusCode::OK, "{catalogue}");
    let projected = catalogue["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|offering| offering["id"] == OFFERING)
        .expect("optional party-count offering");
    assert_eq!(projected["partyCounts"], "optional");
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let mut request = admission(&fx, OFFERING, slot);
    request
        .as_object_mut()
        .expect("an admission object")
        .remove("party");
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "party-optional-resource",
            json!({"hold": null, "admission": request}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    assert!(appointment.get("party").is_none(), "{appointment}");
    assert_eq!(appointment["units"], 1);

    let row = fx
        .admin
        .query_one(
            "SELECT recipient_count, attendee_count FROM scheduling_claims WHERE claim_id=$1",
            &[&Uuid::parse_str(
                appointment["appointmentId"]
                    .as_str()
                    .expect("appointment identifier"),
            )
            .expect("appointment UUID")],
        )
        .await
        .expect("stored resource reservation");
    assert_eq!(row.get::<_, Option<i32>>(0), None);
    assert_eq!(row.get::<_, Option<i32>>(1), None);
}

#[tokio::test]
async fn required_exact_time_and_arrival_window_refuse_missing_or_incoherent_counts() {
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    for (case, party) in [
        ("missing", None),
        ("incoherent", Some(json!({"recipients": 2, "attendees": 1}))),
    ] {
        let mut request = admission(&fx, OFFERING, slot);
        match party {
            Some(party) => request["party"] = party,
            None => {
                request
                    .as_object_mut()
                    .expect("an admission object")
                    .remove("party");
            }
        }
        let (status, refusal) = fx
            .post(
                "/v1/appointments",
                &fx.agent,
                &format!("party-required-{case}"),
                json!({"hold": null, "admission": request}),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refusal}");
        assert_eq!(refusal["code"], "party.capacity-inadequate");
    }

    let start = window_start();
    let window_fx = fixture_with_window(start).await;
    let mut request = arrival(&window_fx, start, None);
    request["admission"]
        .as_object_mut()
        .expect("an admission object")
        .remove("party");
    let (status, refusal) = window_fx
        .post(
            "/v1/appointments",
            &window_fx.agent,
            "party-required-arrival",
            request,
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refusal}");
    assert_eq!(refusal["code"], "party.capacity-inadequate");
}
