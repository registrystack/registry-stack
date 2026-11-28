// SPDX-License-Identifier: Apache-2.0

use super::*;

async fn keyed_bundle_fixture() -> Fixture {
    let mut policy = read_policy(POLICY).expect("the bundle duplicate policy");
    for offering in &mut policy.offerings {
        if offering.id == OFFERING || offering.id == SECOND_OFFERING {
            offering.duplicate_active_key = Some("subject".to_owned());
        }
        if offering.id == SECOND_OFFERING {
            offering.service = "registry-update".to_owned();
        }
    }
    fixture_publishing_policy(
        policy,
        &["north-counter".to_owned(), "two-counter".to_owned()],
    )
    .await
}

fn keyed_bundle_admission(fx: &Fixture, slot: DateTime<Utc>, key: &str) -> Value {
    let mut request = admission(fx, OFFERING, slot);
    request["duplicateKey"] = json!(key);
    request["additionalAllocations"] = json!([{"offering": SECOND_OFFERING}]);
    request
}

#[tokio::test]
async fn a_bundle_checks_the_duplicate_key_for_its_additional_offering() {
    let fx = keyed_bundle_fixture().await;
    let standing_slot = first_slot(&fx, SECOND_OFFERING, 300, 440).await;
    let mut standing = admission(&fx, SECOND_OFFERING, standing_slot);
    standing["duplicateKey"] = json!("subject:bundle-additional");
    let (status, created) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-additional-duplicate-standing",
            json!({"hold": null, "admission": standing}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    let bundle_slot = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-additional-duplicate-refused",
            json!({
                "hold": null,
                "admission": keyed_bundle_admission(
                    &fx,
                    bundle_slot,
                    "subject:bundle-additional",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "booking.duplicate-active");
}

#[tokio::test]
async fn a_bundle_secondary_allocation_is_a_global_duplicate_fact() {
    let fx = keyed_bundle_fixture().await;
    let first_start = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, first) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-secondary-duplicate-first",
            json!({
                "hold": null,
                "admission": keyed_bundle_admission(
                    &fx,
                    first_start,
                    "subject:bundle-secondary-primary",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{first}");

    let direct_slot = first_slot(&fx, SECOND_OFFERING, 480, 620).await;
    let mut direct = admission(&fx, SECOND_OFFERING, direct_slot);
    direct["duplicateKey"] = json!("subject:bundle-secondary-primary");
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-secondary-duplicate-primary-refused",
            json!({"hold": null, "admission": direct}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "booking.duplicate-active");

    let second_slot = first_slot(&fx, OFFERING, 660, 800).await;
    let (status, second) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-secondary-duplicate-second",
            json!({
                "hold": null,
                "admission": keyed_bundle_admission(
                    &fx,
                    second_slot,
                    "subject:bundle-secondary-additional",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{second}");

    let later_slot = first_slot(&fx, OFFERING, 840, 980).await;
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-secondary-duplicate-additional-refused",
            json!({
                "hold": null,
                "admission": keyed_bundle_admission(
                    &fx,
                    later_slot,
                    "subject:bundle-secondary-additional",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "booking.duplicate-active");
}

#[tokio::test]
async fn bundle_duplicate_recheck_excludes_the_rescheduled_appointment() {
    let fx = keyed_bundle_fixture().await;
    let from = first_slot(&fx, OFFERING, 300, 440).await;
    let target = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, appointment) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-duplicate-reschedule-create",
            json!({
                "hold": null,
                "admission": keyed_bundle_admission(
                    &fx,
                    from,
                    "subject:bundle-duplicate-reschedule",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{appointment}");
    let appointment_id = appointment["appointmentId"]
        .as_str()
        .expect("appointment id");

    let (status, moved) = fx
        .post(
            &format!("/v1/appointments/{appointment_id}/reschedule"),
            &fx.agent,
            "bundle-duplicate-reschedule-move",
            json!({
                "observedRevision": appointment["revision"],
                "admission": keyed_bundle_admission(
                    &fx,
                    target,
                    "subject:bundle-duplicate-reschedule",
                ),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moment(&moved, "start"), target);
}

#[tokio::test]
async fn bundle_confirmation_rechecks_global_duplicates_and_keeps_the_hold() {
    let fx = keyed_bundle_fixture().await;
    let held_slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "bundle-confirm-duplicate-hold",
            keyed_bundle_admission(&fx, held_slot, "subject:bundle-confirm"),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");

    let standing_slot = first_slot(&fx, SECOND_OFFERING, 480, 620).await;
    let mut standing = admission(&fx, SECOND_OFFERING, standing_slot);
    standing["duplicateKey"] = json!("subject:bundle-confirm");
    let (status, created) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-confirm-duplicate-standing",
            json!({"hold": null, "admission": standing}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    let hold_id = hold["holdId"].as_str().expect("hold id");
    let (status, refusal) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "bundle-confirm-duplicate-refused",
            json!({"hold": hold_id, "admission": null}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refusal}");
    assert_eq!(refusal["code"], "booking.duplicate-active");
    let state: String = fx
        .admin
        .query_one(
            "SELECT state FROM scheduling_claims WHERE claim_id=$1",
            &[&Uuid::parse_str(hold_id).expect("hold UUID")],
        )
        .await
        .expect("read retained hold")
        .get(0);
    assert_eq!(state, "active");
}

/// A request whose Authorization header is not one bearer credential is
/// refused before the appointment-detail, busy-import, or operational-read
/// authenticator runs, and each refusal still leaves one value-free header
/// diagnostic. Every request gets its own router so the per-verifier limiter
/// starts empty.
#[tokio::test]
async fn header_refusals_on_detail_busy_and_operational_routes_log_one_value_free_diagnostic() {
    use registry_platform_testing::CapturedDiagnosticLogs;
    use tracing::instrument::WithSubscriber;
    let fx = fixture().await;
    let profiles = super::source_busy::profiles();
    let start = pinned_now() + TimeDelta::hours(2);
    let routes = [
        ("GET", format!("/v1/appointments/{}", Uuid::nil()), None),
        (
            "POST",
            "/v1/source-busy/preview?profile=calendar-a".to_owned(),
            Some(super::source_busy::reconciliation(
                0,
                "fresh",
                start,
                json!([]),
            )),
        ),
        (
            "GET",
            super::operational_reads::operational_uri(
                pinned_now(),
                pinned_now() + TimeDelta::days(2),
                "desk",
            ),
            None,
        ),
    ];
    for (method, uri, body) in routes {
        let captured = CapturedDiagnosticLogs::default();
        let request = Request::builder()
            .method(method)
            .uri(&uri)
            .header("authorization", "Basic canary-header-credential")
            .header("content-type", "application/json")
            .body(body.map_or_else(Body::empty, |value: Value| Body::from(value.to_string())))
            .expect("a well-formed test request");
        let response = super::source_busy::source_router(&fx, &profiles)
            .oneshot(request)
            .with_subscriber(captured.subscriber())
            .await
            .expect("an in-process request always answers");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        let rendered = captured.text();
        let diagnostics = refusal_lines(&rendered);
        assert_eq!(diagnostics.len(), 1, "{uri}");
        // Another scheme is a credential this route does not take.
        assert_eq!(
            diagnostics[0]["fields"]["failed_check"], "credential-missing",
            "{uri}"
        );
        assert!(!rendered.contains("canary"), "{uri}");
        assert!(!rendered.contains("Basic"), "{uri}");
    }
}

/// The refusal lines of one captured run: the one fixed message the HTTP
/// edge writes for every refusal.
fn refusal_lines(rendered: &str) -> Vec<Value> {
    rendered
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("JSON diagnostic"))
        .filter(|event| event["fields"]["message"] == "request refused")
        .collect()
}

/// A refusal decided inside the service names the check that refused, in
/// the operator's log line and nowhere in the answer: the same 403 answers a
/// hold that does not exist and a hold the caller holds no task grant for.
#[tokio::test]
async fn service_refusals_log_the_check_that_refused_and_answer_alike() {
    use registry_platform_testing::CapturedDiagnosticLogs;
    use tracing::instrument::WithSubscriber;
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "hold-for-refusal-checks",
            admission(&fx, OFFERING, slot),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    let hold_id = hold["holdId"].as_str().unwrap().to_owned();

    let mut answers = Vec::new();
    for (uri, expected) in [
        (format!("/v1/holds/{}", Uuid::new_v4()), "visibility"),
        (format!("/v1/holds/{hold_id}"), "task-grant-missing"),
    ] {
        let captured = CapturedDiagnosticLogs::default();
        let (status, answer) = fx
            .delete(&uri, &fx.reader)
            .with_subscriber(captured.subscriber())
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(answer["code"], "operation.not-authorized", "{uri}");
        let rendered = captured.text();
        let lines = refusal_lines(&rendered);
        assert_eq!(lines.len(), 1, "{uri}: {rendered}");
        assert_eq!(lines[0]["fields"]["failed_check"], expected, "{uri}");
        assert!(!rendered.contains(&hold_id), "{uri}");
        let mut answer = answer;
        answer
            .as_object_mut()
            .expect("a problem body")
            .remove("traceId");
        answers.push(answer);
    }
    assert_eq!(
        answers[0], answers[1],
        "the check never reaches the caller: a missing and an unreachable hold answer alike"
    );
}

/// The check a foreign caller's refusal names says why it was refused: a
/// reschedule, a cancellation, and a release of another caller's target are
/// ownership refusals, and a read it holds no grant action for is a grant
/// scope refusal. The answers are the same 403 `operation.not-authorized`.
#[tokio::test]
async fn a_foreign_callers_refusals_name_ownership_and_grant_scope() {
    use registry_platform_testing::CapturedDiagnosticLogs;
    use tracing::instrument::WithSubscriber;
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, created) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "foreign-checks-appointment",
            json!({"hold": null, "admission": admission(&fx, OFFERING, slot)}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let appointment_id = created["appointmentId"].as_str().unwrap().to_owned();
    let held = first_slot(&fx, OFFERING, 480, 620).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "foreign-checks-hold",
            admission(&fx, OFFERING, held),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    let hold_id = hold["holdId"].as_str().unwrap().to_owned();
    let stranger = agent_token_for("principal-stranger");
    let other = first_slot(&fx, OFFERING, 640, 700).await;
    for (method, uri, key, body, expected) in [
        (
            "POST",
            format!("/v1/appointments/{appointment_id}/reschedule"),
            Some("foreign-checks-reschedule"),
            Some(json!({"observedRevision": 0, "admission": admission(&fx, OFFERING, other)})),
            "ownership",
        ),
        (
            "POST",
            format!("/v1/appointments/{appointment_id}/cancel"),
            Some("foreign-checks-cancel"),
            Some(json!({"observedRevision": 0, "reason": null})),
            "ownership",
        ),
        (
            "DELETE",
            format!("/v1/holds/{hold_id}"),
            None,
            None,
            "ownership",
        ),
        (
            "GET",
            format!("/v1/appointments/{appointment_id}"),
            None,
            None,
            "task-grant-scope",
        ),
    ] {
        let captured = CapturedDiagnosticLogs::default();
        let (status, answer) = fx
            .request(method, &uri, &stranger, key, body)
            .with_subscriber(captured.subscriber())
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
        assert_eq!(answer["code"], "operation.not-authorized", "{method} {uri}");
        let lines = refusal_lines(&captured.text());
        assert_eq!(lines.len(), 1, "{method} {uri}");
        assert_eq!(
            lines[0]["fields"]["failed_check"], expected,
            "{method} {uri}"
        );
    }
}

/// The task grant the booking agent carries, with a day left on it and the
/// attendance action added: past the offline path's fifteen-minute cap.
fn long_lived_agent_token() -> String {
    let mut grant = grant_claims();
    grant["registry_grant_exp"] = json!(pinned_now().timestamp() + 86_400);
    grant["registry_grant_bounds"]["permissions"][0]["actions"]
        .as_array_mut()
        .expect("the actions are a list")
        .push(json!("attendance.record"));
    let mut claims = json!({
        "sub": "principal-agent",
        "azp": CLIENT,
        "registry_scopes": "scheduling-read scheduling-explain",
        "registry_actor_kind": "service",
    });
    claims
        .as_object_mut()
        .expect("claims are an object")
        .extend(
            grant
                .as_object()
                .expect("grant claims are an object")
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    token(claims)
}

/// SCHEDULING-DEC-01. On a route that names an existing hold or appointment,
/// a grant with too much lifetime left answers `operation.not-authorized`,
/// the same answer an unknown id gives, so the answer never says whether the
/// id exists. The operator's line still names `task-grant-lifetime`.
#[tokio::test]
async fn an_id_addressed_route_answers_an_existing_and_an_unknown_id_alike_under_a_long_grant() {
    use registry_platform_testing::CapturedDiagnosticLogs;
    use tracing::instrument::WithSubscriber;
    let fx = fixture().await;
    let long = long_lived_agent_token();
    let held = first_slot(&fx, OFFERING, 300, 440).await;
    let (status, hold) = fx
        .post(
            "/v1/holds",
            &fx.agent,
            "long-grant-hold",
            admission(&fx, OFFERING, held),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{hold}");
    let hold_id = hold["holdId"].as_str().unwrap().to_owned();
    let (appointment_id, revision) = booked(&fx, 480, 620, "long-grant-appointment").await;
    let other = first_slot(&fx, OFFERING, 640, 700).await;
    let unknown = Uuid::new_v4().to_string();

    let routes = |hold: &str, appointment: &str| {
        vec![
            ("release", "DELETE", format!("/v1/holds/{hold}"), None, None),
            (
                "confirm",
                "POST",
                "/v1/appointments".to_owned(),
                Some("long-grant-confirm"),
                Some(json!({"hold": hold, "admission": null})),
            ),
            (
                "reschedule",
                "POST",
                format!("/v1/appointments/{appointment}/reschedule"),
                Some("long-grant-reschedule"),
                Some(
                    json!({"observedRevision": revision, "admission": admission(&fx, OFFERING, other)}),
                ),
            ),
            (
                "attendance",
                "PUT",
                format!("/v1/appointments/{appointment}/attendance"),
                Some("long-grant-attendance"),
                Some(json!({
                    "observedAppointmentRevision": revision,
                    "observedRevision": 0,
                    "state": "arrived",
                    "observedAt": stamp(pinned_now() - TimeDelta::minutes(5)),
                })),
            ),
            (
                "cancel",
                "POST",
                format!("/v1/appointments/{appointment}/cancel"),
                Some("long-grant-cancel"),
                Some(json!({"observedRevision": revision, "reason": null})),
            ),
        ]
    };
    let existing_routes = routes(&hold_id, &appointment_id);
    let unknown_routes = routes(&unknown, &unknown);
    for (existing, missing) in existing_routes.into_iter().zip(unknown_routes) {
        let (label, method, uri, key, body) = existing;
        let mut answers = Vec::new();
        let mut checks = Vec::new();
        for (target, (_, method, uri, key, body)) in [
            ("existing", (label, method, uri, key, body)),
            ("unknown", missing),
        ] {
            let captured = CapturedDiagnosticLogs::default();
            let (status, mut answer) = fx
                .request(method, &uri, &long, key, body)
                .with_subscriber(captured.subscriber())
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{label} {target}: {answer}");
            assert_eq!(
                answer["code"], "operation.not-authorized",
                "{label} {target}"
            );
            answer
                .as_object_mut()
                .expect("a problem body")
                .remove("traceId");
            answers.push(answer);
            let lines = refusal_lines(&captured.text());
            assert_eq!(lines.len(), 1, "{label} {target}");
            checks.push(lines[0]["fields"]["failed_check"].clone());
        }
        assert_eq!(
            answers[0], answers[1],
            "{label}: an existing id and an unknown id answer alike"
        );
        assert_eq!(checks, ["task-grant-lifetime", "visibility"], "{label}");
    }

    // No caller-named id is involved: a new hold keeps the specific code. A
    // fresh deployment keeps this line clear of the per-check log limit the
    // five routes above used up.
    let fx = fixture().await;
    let other = first_slot(&fx, OFFERING, 640, 700).await;
    let captured = CapturedDiagnosticLogs::default();
    let (status, answer) = fx
        .post(
            "/v1/holds",
            &long,
            "long-grant-new-hold",
            admission(&fx, OFFERING, other),
        )
        .with_subscriber(captured.subscriber())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["code"], "grant.lifetime-too-long");
    let lines = refusal_lines(&captured.text());
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["fields"]["failed_check"], "task-grant-lifetime");
}

/// A task grant that lapses between the request's admission and the capacity
/// transaction's decision-time re-check is a lapsed grant, not an ownership
/// refusal.
#[tokio::test]
async fn a_grant_that_lapses_inside_the_transaction_is_counted_as_expired() {
    use registry_platform_testing::CapturedDiagnosticLogs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tracing::instrument::WithSubscriber;
    let fx = fixture().await;
    let slot = first_slot(&fx, OFFERING, 90, 200).await;
    let door = pinned_now();
    let observations = Arc::new(AtomicUsize::new(0));
    let observed = observations.clone();
    fx.store.pin_clock(Arc::new(move || {
        if observed.fetch_add(1, Ordering::SeqCst) == 0 {
            door
        } else {
            door + TimeDelta::minutes(20)
        }
    }));
    let captured = CapturedDiagnosticLogs::default();
    let (status, problem) = fx
        .post(
            "/v1/appointments",
            &fx.agent,
            "lapsed-in-transaction",
            json!({"hold": null, "admission": admission(&fx, OFFERING, slot)}),
        )
        .with_subscriber(captured.subscriber())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
    assert_eq!(problem["code"], "operation.not-authorized");
    let lines = refusal_lines(&captured.text());
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["fields"]["failed_check"], "task-grant-expired");
}

/// A caller with the reads scope and no task grant, reading another
/// caller's appointment, is refused on ownership.
#[tokio::test]
async fn a_reads_scope_caller_reading_another_owners_appointment_is_an_ownership_refusal() {
    use registry_platform_testing::CapturedDiagnosticLogs;
    use tracing::instrument::WithSubscriber;
    let fx = fixture().await;
    let (appointment_id, _) = booked(&fx, 300, 440, "reads-scope-foreign").await;
    let captured = CapturedDiagnosticLogs::default();
    let (status, answer) = fx
        .get(&format!("/v1/appointments/{appointment_id}"), &fx.reader)
        .with_subscriber(captured.subscriber())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["code"], "operation.not-authorized");
    let lines = refusal_lines(&captured.text());
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["fields"]["failed_check"], "ownership");
}

/// A read refused for its scope names the values the operator declared: the
/// claim that carries scopes and the scope the route needs. The scope the
/// token carries never reaches the line, and the answer is the same 403.
#[tokio::test]
async fn a_scope_refusal_line_names_the_declared_scope_and_none_of_the_tokens() {
    use registry_platform_testing::CapturedDiagnosticLogs;
    use tracing::instrument::WithSubscriber;
    let fx = fixture().await;
    let canary = "canary-token-scope-4d8e";
    let holder = operational_token("principal-canary", canary);
    let captured = CapturedDiagnosticLogs::default();
    let (status, answer) = fx
        .get("/v1/offerings", &holder)
        .with_subscriber(captured.subscriber())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["code"], "profile.not-authorized");
    let rendered = captured.text();
    assert!(!rendered.contains(canary), "{rendered}");
    let lines = refusal_lines(&rendered);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["fields"]["failed_check"], "scope");
    assert_eq!(lines[0]["fields"]["scope_claim"], "registry_scopes");
    assert_eq!(lines[0]["fields"]["required_scope"], "scheduling-read");
    assert!(lines[0]["fields"].get("access_profile").is_none());
}
