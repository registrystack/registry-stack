//! Every refusal the Evidence boundary answers with 401, 403 or 429 is counted
//! under the check that failed, logged once with that check, and answered with
//! the bytes it has always had.
//!
//! The golden file holds each answer's status, headers and body (minus the
//! per-request trace id). It was written from the tree before the check was
//! threaded through, so a pass proves no refusal answer changed.
//! `REGISTRY_EVIDENCE_WRITE_GOLDEN=1` rewrites it.

use super::*;
use registry_platform_authcommon::FailedCheck;

const GOLDEN: &str = "tests/golden/refusal_answers.json";
const TOKEN_CANARY: &str = "refusal-token-canary-value";
const CLIENT_CANARY: &str = "refusal-client-canary-value";

/// What the request carries besides its route.
enum Credential {
    Absent,
    Header(&'static str),
    Repeated,
    Token(String),
}

struct Scenario {
    name: &'static str,
    method: &'static str,
    route: &'static str,
    credential: Credential,
    accept: Option<&'static str>,
    body: Option<EvidenceRequest>,
    status: StatusCode,
    check: FailedCheck,
}

fn evidence(
    name: &'static str,
    credential: Credential,
    body: EvidenceRequest,
    status: StatusCode,
    check: FailedCheck,
) -> Scenario {
    Scenario {
        name,
        method: "POST",
        route: "/v1/evidence",
        credential,
        accept: None,
        body: Some(body),
        status,
        check,
    }
}

fn claims_without(removed: &[&str], replaced: Value) -> Value {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": "requester-principal-canary",
        "iat": now - 1,
        "exp": now + 298,
        "client_id": "evidence-task-agent",
        "registry_actor_kind": "service",
        "evidence_tags": ["fixture-agency"],
        "evidence_audience": EVIDENCE_AUDIENCE
    });
    let object = claims.as_object_mut().expect("claims are an object");
    for name in removed {
        object.remove(*name);
    }
    object.extend(
        replaced
            .as_object()
            .expect("replacements are an object")
            .clone(),
    );
    claims
}

/// A well-formed token whose signature segment is not the signature of its
/// payload.
fn token_with_tampered_signature() -> String {
    let token = access_token(None);
    let (signing_input, _) = token.rsplit_once('.').expect("a compact token");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode([0u8; 64]))
}

/// A token whose header names a key the verifier does not hold.
fn token_with_unknown_key() -> String {
    let token = access_token(None);
    let mut segments = token.split('.');
    let _ = segments.next();
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({"alg": "ES256", "kid": "unknown-key", "typ": "at+jwt"}))
            .expect("header serializes"),
    );
    format!(
        "{header}.{}.{}",
        segments.next().expect("payload"),
        segments.next().expect("signature")
    )
}

fn scenarios() -> Vec<Scenario> {
    let now = Utc::now().timestamp();
    let adult = adult_request;
    let mut wrong_purpose = adult_request();
    wrong_purpose.purpose = "no-such-purpose".to_owned();
    let mut unknown_profile = adult_request();
    unknown_profile.subjects[0].selector.profile = "no-such-profile".to_owned();
    let mut pinned = adult_request();
    pinned.expected_configuration_revision = Some(format!("sha256:{}", "0".repeat(64)));
    let unauthorized = StatusCode::UNAUTHORIZED;
    let forbidden = StatusCode::FORBIDDEN;
    vec![
        evidence(
            "no-authorization-header",
            Credential::Absent,
            adult(),
            unauthorized,
            FailedCheck::CredentialMissing,
        ),
        evidence(
            "non-bearer-scheme",
            Credential::Header("Basic abc"),
            adult(),
            unauthorized,
            FailedCheck::CredentialMissing,
        ),
        evidence(
            "repeated-authorization-header",
            Credential::Repeated,
            adult(),
            unauthorized,
            FailedCheck::CredentialMalformed,
        ),
        evidence(
            "double-space-separator",
            Credential::Header("Bearer  abc"),
            adult(),
            unauthorized,
            FailedCheck::CredentialMalformed,
        ),
        evidence(
            "not-a-compact-token",
            Credential::Header("Bearer refusal-token-canary-value"),
            adult(),
            unauthorized,
            FailedCheck::CredentialMalformed,
        ),
        evidence(
            "wrong-issuer",
            Credential::Token(access_token_for_issuer(
                "https://other.invalid",
                "requester-principal-canary",
                None,
            )),
            adult(),
            unauthorized,
            FailedCheck::TokenIssuer,
        ),
        evidence(
            "expired-token",
            Credential::Token(signed_access_token(claims_without(
                &[],
                json!({"iat": now - 900, "exp": now - 600}),
            ))),
            adult(),
            unauthorized,
            FailedCheck::TokenTime,
        ),
        evidence(
            "wrong-audience",
            Credential::Token(signed_access_token(claims_without(
                &[],
                json!({"aud": "https://other.invalid/audience"}),
            ))),
            adult(),
            unauthorized,
            FailedCheck::TokenAudience,
        ),
        evidence(
            "unknown-key",
            Credential::Token(token_with_unknown_key()),
            adult(),
            unauthorized,
            FailedCheck::TokenKey,
        ),
        evidence(
            "tampered-signature",
            Credential::Token(token_with_tampered_signature()),
            adult(),
            unauthorized,
            FailedCheck::TokenSignature,
        ),
        evidence(
            "client-not-admitted",
            Credential::Token(signed_access_token(claims_without(
                &[],
                json!({"client_id": CLIENT_CANARY}),
            ))),
            adult(),
            unauthorized,
            FailedCheck::TokenClient,
        ),
        evidence(
            "sender-constrained-token",
            Credential::Token(signed_access_token(claims_without(
                &[],
                json!({"cnf": {"jkt": "thumbprint"}}),
            ))),
            adult(),
            unauthorized,
            FailedCheck::SenderConstraint,
        ),
        evidence(
            "unknown-actor-kind",
            Credential::Token(signed_access_token(claims_without(
                &[],
                json!({"registry_actor_kind": "not-a-kind"}),
            ))),
            adult(),
            unauthorized,
            FailedCheck::ActorKind,
        ),
        evidence(
            "evidence-audience-claim-is-not-a-url",
            Credential::Token(signed_access_token(claims_without(
                &[],
                json!({"evidence_audience": "not a url"}),
            ))),
            adult(),
            unauthorized,
            FailedCheck::TokenClaims,
        ),
        evidence(
            "requester-tags-claim-absent",
            Credential::Token(signed_access_token(claims_without(
                &["evidence_tags"],
                json!({}),
            ))),
            adult(),
            unauthorized,
            FailedCheck::TokenClaims,
        ),
        evidence(
            "expired-task-grant",
            Credential::Token(access_token(Some({
                let mut grant = parent_grant_claims();
                grant["registry_grant_exp"] = json!(now - 1);
                grant
            }))),
            adult(),
            forbidden,
            FailedCheck::TaskGrantExpired,
        ),
        Scenario {
            name: "batch-without-credential",
            method: "POST",
            route: "/v1/evidence/batch",
            credential: Credential::Absent,
            accept: None,
            body: None,
            status: unauthorized,
            check: FailedCheck::CredentialMissing,
        },
        Scenario {
            name: "discovery-without-credential",
            method: "GET",
            route: "/v1/evidence-definitions",
            credential: Credential::Absent,
            accept: None,
            body: None,
            status: unauthorized,
            check: FailedCheck::CredentialMissing,
        },
        Scenario {
            name: "discovery-with-wrong-issuer",
            method: "GET",
            route: "/v1/evidence-definitions",
            credential: Credential::Token(access_token_for_issuer(
                "https://other.invalid",
                "requester-principal-canary",
                None,
            )),
            accept: None,
            body: None,
            status: unauthorized,
            check: FailedCheck::TokenIssuer,
        },
        evidence(
            "no-entitlement-for-the-requester",
            Credential::Token(access_token(Some(
                json!({"evidence_tags": ["unmatched-agency"]}),
            ))),
            adult(),
            forbidden,
            FailedCheck::AccessProfile,
        ),
        evidence(
            "purpose-not-permitted",
            Credential::Token(access_token(None)),
            wrong_purpose,
            forbidden,
            FailedCheck::Purpose,
        ),
        evidence(
            "selector-profile-not-granted",
            Credential::Token(access_token(None)),
            unknown_profile,
            forbidden,
            FailedCheck::SubjectSelector,
        ),
        evidence(
            "revision-pin-mismatch",
            Credential::Token(access_token(None)),
            pinned,
            forbidden,
            FailedCheck::RevisionPin,
        ),
        Scenario {
            name: "response-format-not-permitted",
            method: "POST",
            route: "/v1/evidence",
            credential: Credential::Token(access_token(None)),
            accept: Some(EVIDENCE_SD_JWT_VC_MEDIA_TYPE),
            body: Some(adult_request()),
            status: forbidden,
            check: FailedCheck::Disclosure,
        },
    ]
}

fn build_request(scenario: &Scenario) -> HttpRequest<Body> {
    let mut builder = HttpRequest::builder()
        .method(scenario.method)
        .uri(scenario.route)
        .header("content-type", "application/json");
    match &scenario.credential {
        Credential::Absent => {}
        Credential::Header(value) => builder = builder.header("authorization", *value),
        Credential::Repeated => {
            builder = builder
                .header("authorization", "Bearer first.second.third")
                .header("authorization", "Bearer first.second.third");
        }
        Credential::Token(token) => {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
    }
    if let Some(accept) = scenario.accept {
        builder = builder.header("accept", accept);
    }
    let body = scenario.body.as_ref().map_or_else(Body::empty, |body| {
        Body::from(serde_json::to_vec(body).expect("the request serializes"))
    });
    builder.body(body).expect("the request builds")
}

/// The family line of `evidence_request_refusals_total` for one check, or zero
/// when the exposition carries no such series.
fn counted(exposition: &str, check: FailedCheck) -> u64 {
    let prefix = format!(
        "evidence_request_refusals_total{{check=\"{}\"}} ",
        check.as_str()
    );
    exposition
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map_or(0, |value| value.parse().expect("a counter value"))
}

struct Observed {
    answer: Value,
    exposition: String,
}

/// Serve one scenario on a fresh runtime, so its counter and log budget are its
/// own, and return what the caller received and what the registry then held.
async fn serve(scenario: &Scenario) -> Observed {
    let fixture = acceptance_runtime().await;
    let (app, metrics) = build_app_with_metrics(Arc::clone(&fixture.runtime));
    let response = app
        .oneshot(build_request(scenario))
        .await
        .expect("the router answers");
    let status = response.status();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .map(|value| value.to_str().expect("ASCII header").to_owned())
    };
    let headers = json!({
        "content-type": header("content-type"),
        "www-authenticate": header("www-authenticate"),
        "retry-after": header("retry-after"),
        "cache-control": header("cache-control"),
        "vary": header("vary"),
    });
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body reads");
    let mut body: Value = serde_json::from_slice(&bytes).expect("a problem body");
    body.as_object_mut()
        .expect("a problem object")
        .insert("traceId".to_owned(), json!("<trace>"));
    Observed {
        answer: json!({"status": status.as_u16(), "headers": headers, "body": body}),
        exposition: metrics.render(),
    }
}

fn golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN)
}

#[test]
fn every_refusal_is_counted_logged_once_by_its_check_and_answered_as_before() {
    let scenarios = scenarios();
    let mut answers = serde_json::Map::new();
    let mut failures = Vec::new();
    for scenario in &scenarios {
        let slot: Arc<Mutex<Option<Observed>>> = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&slot);
        let emitted = capture_evidence_logs(|| async {
            *sink.lock().expect("observation slot") = Some(serve(scenario).await);
        });
        let observed = slot
            .lock()
            .expect("observation slot")
            .take()
            .expect("the scenario ran");
        answers.insert(scenario.name.to_owned(), observed.answer.clone());

        if observed.answer["status"] != json!(scenario.status.as_u16()) {
            failures.push(format!(
                "{}: status {} where {} was expected",
                scenario.name, observed.answer["status"], scenario.status
            ));
            continue;
        }
        let count = counted(&observed.exposition, scenario.check);
        if count != 1 {
            failures.push(format!(
                "{}: the {} series counted {count}, expected 1",
                scenario.name,
                scenario.check.as_str()
            ));
        }
        for other in FailedCheck::ALL {
            if other != scenario.check && counted(&observed.exposition, other) != 0 {
                failures.push(format!(
                    "{}: {} was counted as well",
                    scenario.name,
                    other.as_str()
                ));
            }
        }
        let refused: Vec<&Value> = emitted
            .iter()
            .filter(|record| record["fields"]["decision"] == json!("refused"))
            .collect();
        if refused.len() != 1
            || refused[0]["fields"]["failed_check"] != json!(scenario.check.as_str())
        {
            failures.push(format!(
                "{}: expected one refused line for {}, saw {refused:?}",
                scenario.name,
                scenario.check.as_str()
            ));
        }
        let raw = serde_json::to_string(&emitted).expect("captured records serialize");
        for canary in [TOKEN_CANARY, CLIENT_CANARY, "requester-principal-canary"] {
            if raw.contains(canary) {
                failures.push(format!("{}: a log line carried {canary}", scenario.name));
            }
        }
    }

    let answers = Value::Object(answers);
    if std::env::var_os("REGISTRY_EVIDENCE_WRITE_GOLDEN").is_some() {
        let mut text = serde_json::to_string_pretty(&answers).expect("the golden serializes");
        text.push('\n');
        fs::write(golden_path(), text).expect("the golden is written");
    } else {
        let golden: Value = serde_json::from_str(
            &fs::read_to_string(golden_path()).expect("the golden file is readable"),
        )
        .expect("the golden parses");
        assert_eq!(answers, golden, "a refusal answer changed");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A request over the per-principal budget is a `429` counted under
/// `rate-limit`, with its `Retry-After` unchanged.
#[tokio::test]
async fn a_request_over_the_rate_budget_is_counted_under_rate_limit() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    mutate_acceptance_configuration(&configuration_path, |configuration| {
        configuration["rateLimits"]["requestsPerPrincipalPerMinute"] = json!(1);
        configuration["rateLimits"]["burstPerPrincipal"] = json!(1);
    });
    refresh_package_envelope(&prepared.bundle_root);
    make_read_only(&prepared.bundle_root);
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("rate-limited runtime initializes"),
    );
    let (app, metrics) = build_app_with_metrics(runtime);
    let http = TestServer::new(app);
    let token = access_token(None);

    http.get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {token}"))
        .await
        .assert_status_ok();
    assert_eq!(counted(&metrics.render(), FailedCheck::RateLimit), 0);
    let limited = http
        .get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(limited.status_code(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.header("retry-after"), "1");
    assert_eq!(limited.header("content-type"), "application/problem+json");
    assert_eq!(limited.header("cache-control"), "no-store");
    let body: Value = limited.json();
    assert_eq!(body["status"], json!(429));
    assert_eq!(body["code"], json!("evidence.rate-limited"));
    assert_eq!(body["title"], json!("Evidence request rate is exhausted"));
    assert_eq!(
        body["detail"],
        json!("the Evidence request rate is exhausted")
    );
    assert_eq!(counted(&metrics.render(), FailedCheck::RateLimit), 1);
}
