// SPDX-License-Identifier: Apache-2.0

//! The authentication and profile refusals Casework answers on its HTTP
//! surface, frozen against a checked-in file.
//!
//! Each case drives the real router and records the status, the headers a
//! caller can act on, and the problem body with its `traceId` removed. A
//! change to what a caller sees changes `golden/refusal_responses.json`.
//! `REGISTRY_UPDATE_GOLDEN=1` rewrites the file, and a reviewer reads the
//! diff.
//!
//! Each case also checks what the operator sees: the refusal counts once under
//! its check, and writes one log line that names the check and nothing a
//! caller sent.
//!
//! The router's store points at a PostgreSQL address nothing listens on:
//! every case here is refused before a handler reaches the store.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, Response};
use registry_casework::{
    router_with_recorder, CaseworkAuthenticator, CaseworkService, DatabaseConfig, HttpState,
    HumanIdentityConfig, PostgresStore,
};
use registry_casework_core::{
    AccessProfile, CaseworkActsAs, CaseworkProject, InboxPolicy, ProjectIdentity, QueuePolicy,
    CASEWORK_API_VERSION, CASEWORK_KIND,
};
use registry_platform_authcommon::{FailedCheck, RefusalRecorder};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, CapturedDiagnosticLogs, MockIdp};
use serde_json::{json, Map, Value};
use tower::ServiceExt as _;
use tracing::instrument::WithSubscriber as _;

const AUDIENCE: &str = "urn:test:casework";
const PRINCIPAL: &str = "urn:test:person:refusal-golden";
const PROFILE_HEADER: &str = "registry-casework-profile";
const SOURCE_AUTHORIZATION_HEADER: &str = "registry-source-authorization";
const SOURCE_PROFILE_HEADER: &str = "registry-source-profile";
const DELEGATED_READER_HEADER: &str = "registry-casework-delegated-reader";
const TASK_ID: &str = "00000000-0000-4000-8000-000000000001";
const GRANT_ID: &str = "00000000-0000-4000-8000-000000000002";

struct Case {
    name: &'static str,
    /// The check the operator's counter and log line name for this refusal.
    check: &'static str,
    method: &'static str,
    path: String,
    headers: Vec<(&'static str, String)>,
}

fn case(
    name: &'static str,
    check: &'static str,
    method: &'static str,
    path: &str,
    headers: Vec<(&'static str, String)>,
) -> Case {
    Case {
        name,
        check,
        method,
        path: path.to_owned(),
        headers,
    }
}

/// The scope a token holds in the cases that refuse on scope. It is the
/// caller's value, so no log line may carry it.
const HELD_CANARY_SCOPE: &str = "casework:unrelated";

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn claims(scope: &str, kind: Option<&str>) -> Value {
    let mut claims = json!({
        "aud": AUDIENCE,
        "registry_principal": PRINCIPAL,
        "scope": scope,
    });
    if let Some(kind) = kind {
        claims["registry_actor_kind"] = json!(kind);
    }
    claims
}

fn with(mut claims: Value, extra: Value) -> Value {
    claims
        .as_object_mut()
        .expect("claims are an object")
        .extend(extra.as_object().expect("extra is an object").clone());
    claims
}

fn cases(idp: &MockIdp) -> Vec<Case> {
    let staff = idp.mint_token(claims("casework:staff", Some("human")));
    let service_on_staff = idp.mint_token(claims("casework:staff", Some("service")));
    let requester = idp.mint_token(claims("casework:request", Some("service")));
    let other_scope = idp.mint_token(claims("casework:unrelated", Some("human")));
    let wrong_audience = idp.mint_token(with(
        claims("casework:staff", Some("human")),
        json!({"aud": "urn:test:other-service"}),
    ));
    let expired = idp.mint_token(with(
        claims("casework:staff", Some("human")),
        json!({"exp": chrono::Utc::now().timestamp() - 120}),
    ));
    let no_principal = idp.mint_token(json!({
        "aud": AUDIENCE,
        "scope": "casework:staff",
        "registry_actor_kind": "human",
    }));
    let delegated = idp.mint_token(with(
        claims("casework:staff", Some("human")),
        json!({"act": {"sub": "agent"}}),
    ));
    let grant_bearing = idp.mint_token(with(
        claims("casework:staff", Some("human")),
        json!({"registry_grant_id": "grant"}),
    ));
    let mut bad_signature = staff.clone();
    let last = bad_signature.pop().expect("a token is not empty");
    bad_signature.push(if last == 'A' { 'B' } else { 'A' });

    let list = "/v1/review-tasks";
    let as_staff = |token: &str| {
        vec![
            ("authorization", bearer(token)),
            (PROFILE_HEADER, "staff".to_owned()),
        ]
    };
    let assertion = format!("/v1/task-grants/{GRANT_ID}/assertion");
    let history = format!("/v1/review-requests/{TASK_ID}/history");
    vec![
        case(
            "no-authorization",
            "credential-missing",
            "GET",
            list,
            vec![(PROFILE_HEADER, "staff".to_owned())],
        ),
        case(
            "basic-scheme",
            "credential-missing",
            "GET",
            list,
            vec![
                ("authorization", "Basic abc".to_owned()),
                (PROFILE_HEADER, "staff".to_owned()),
            ],
        ),
        case(
            "bearer-with-two-tokens",
            "credential-malformed",
            "GET",
            list,
            vec![
                ("authorization", "Bearer one two".to_owned()),
                (PROFILE_HEADER, "staff".to_owned()),
            ],
        ),
        case(
            "bearer-not-a-compact-token",
            "credential-malformed",
            "GET",
            list,
            as_staff("not-a-token"),
        ),
        case(
            "bad-signature",
            "token-signature",
            "GET",
            list,
            as_staff(&bad_signature),
        ),
        case(
            "wrong-audience",
            "token-audience",
            "GET",
            list,
            as_staff(&wrong_audience),
        ),
        case("expired", "token-time", "GET", list, as_staff(&expired)),
        case(
            "missing-principal",
            "token-claims",
            "GET",
            list,
            as_staff(&no_principal),
        ),
        case(
            "act-on-officer-profile",
            "delegation",
            "GET",
            list,
            as_staff(&delegated),
        ),
        case(
            "grant-claims-on-officer-profile",
            "task-grant-claims",
            "GET",
            list,
            as_staff(&grant_bearing),
        ),
        case(
            "unknown-profile",
            "access-profile",
            "GET",
            list,
            vec![
                ("authorization", bearer(&staff)),
                (PROFILE_HEADER, "nobody".to_owned()),
            ],
        ),
        case(
            "scope-missing",
            "scope",
            "GET",
            list,
            as_staff(&other_scope),
        ),
        case(
            "service-on-human-profile",
            "actor-kind",
            "GET",
            list,
            as_staff(&service_on_staff),
        ),
        case(
            "task-assertion-with-a-profile-header",
            "access-profile",
            "POST",
            &assertion,
            as_staff(&staff),
        ),
        case(
            "task-assertion-no-authorization",
            "credential-missing",
            "POST",
            &assertion,
            vec![],
        ),
        case(
            "task-assertion-bearer-not-a-compact-token",
            "credential-malformed",
            "POST",
            &assertion,
            vec![("authorization", bearer("not-a-token"))],
        ),
        case(
            "task-assertion-without-its-scope",
            "scope",
            "POST",
            &assertion,
            vec![("authorization", bearer(&staff))],
        ),
        case(
            "delegated-read-with-a-profile-header",
            "access-profile",
            "GET",
            "/v1/delegated-staff/review-tasks",
            as_staff(&staff),
        ),
        case(
            "delegated-read-no-authorization",
            "credential-missing",
            "GET",
            "/v1/delegated-staff/review-tasks",
            vec![(DELEGATED_READER_HEADER, "reader".to_owned())],
        ),
        case(
            "delegated-read-unknown-policy",
            "access-profile",
            "GET",
            "/v1/delegated-staff/review-tasks",
            vec![
                ("authorization", bearer(&staff)),
                (DELEGATED_READER_HEADER, "reader".to_owned()),
            ],
        ),
        case(
            "supervision-list-on-a-staff-profile",
            "operation",
            "GET",
            "/v1/review-tasks/supervision",
            as_staff(&staff),
        ),
        case(
            "reviewer-list-on-a-requester-profile",
            "operation",
            "GET",
            list,
            vec![
                ("authorization", bearer(&requester)),
                (PROFILE_HEADER, "requester".to_owned()),
            ],
        ),
        case(
            "source-bearer-with-two-tokens",
            "credential-malformed",
            "GET",
            &history,
            vec![
                ("authorization", bearer(&staff)),
                (PROFILE_HEADER, "staff".to_owned()),
                (SOURCE_AUTHORIZATION_HEADER, "Bearer one two".to_owned()),
                (SOURCE_PROFILE_HEADER, "review-agent".to_owned()),
            ],
        ),
        case(
            "source-bearer-not-a-compact-token",
            "credential-malformed",
            "GET",
            &history,
            vec![
                ("authorization", bearer(&staff)),
                (PROFILE_HEADER, "staff".to_owned()),
                (SOURCE_AUTHORIZATION_HEADER, bearer("not-a-token")),
                (SOURCE_PROFILE_HEADER, "review-agent".to_owned()),
            ],
        ),
        case(
            "source-pair-on-a-requester-profile",
            "access-profile",
            "GET",
            &history,
            vec![
                ("authorization", bearer(&requester)),
                (PROFILE_HEADER, "requester".to_owned()),
                (SOURCE_AUTHORIZATION_HEADER, bearer(&staff)),
                (SOURCE_PROFILE_HEADER, "review-agent".to_owned()),
            ],
        ),
        case(
            "source-bearer-refused-by-a-staff-profile-scope",
            "scope",
            "GET",
            &history,
            vec![
                ("authorization", bearer(&other_scope)),
                (PROFILE_HEADER, "staff".to_owned()),
                (SOURCE_AUTHORIZATION_HEADER, bearer(&staff)),
                (SOURCE_PROFILE_HEADER, "review-agent".to_owned()),
            ],
        ),
    ]
}

fn profile(id: &str, scope: &str, role: CaseworkActsAs) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        label: None,
        description: None,
        principal_claim: "registry_principal".to_owned(),
        required_scopes: vec![scope.to_owned()],
        acts_as: role,
    }
}

fn project() -> CaseworkProject {
    let starter = CaseworkProject::from_slice(include_bytes!(
        "../../../products/casework/examples/standalone-decision/casework.yaml"
    ))
    .expect("canonical review fixture");
    CaseworkProject {
        task_templates: Vec::new(),
        api_version: CASEWORK_API_VERSION.to_owned(),
        kind: CASEWORK_KIND.to_owned(),
        project: ProjectIdentity::new("refusal-golden-test".parse().unwrap(), "1".to_owned()),
        access_profiles: vec![
            profile("staff", "casework:staff", CaseworkActsAs::Staff),
            profile("requester", "casework:request", CaseworkActsAs::Requester),
        ],
        queues: vec![QueuePolicy {
            id: "decisions".to_owned(),
            label: "Decisions".to_owned(),
        }],
        teams: starter.teams,
        context_providers: Vec::new(),
        review_policies: starter.review_policies,
        trusted_producers: starter.trusted_producers,
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
    }
}

/// A store whose pool has no server behind it. It connects only when used.
fn unconnected_store(root: &std::path::Path) -> PostgresStore {
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::fs::canonicalize(root).expect("canonical secret root");
    let secrets_dir = root.join("secrets");
    std::fs::create_dir(&secrets_dir).expect("secret directory");
    std::fs::set_permissions(&secrets_dir, std::fs::Permissions::from_mode(0o700))
        .expect("private secret directory");
    let file = secrets_dir.join("database-url");
    std::fs::write(&file, "postgresql://casework@127.0.0.1:9/casework").expect("database url");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
        .expect("private database url");
    let secrets =
        SecretResolver::new([SecretProvider::File], &secrets_dir).expect("secret resolver");
    PostgresStore::connect_runtime(
        &DatabaseConfig {
            runtime_url_ref: "secret:file/database-url".to_owned(),
            migration_url_ref: "secret:file/database-url".to_owned(),
            ca_bundle_ref: None,
            test_only_plaintext: false,
            transport: None,
        },
        &secrets,
    )
    .expect("an unconnected runtime store")
}

fn app(idp: &MockIdp, root: &std::path::Path, recorder: Arc<RefusalRecorder>) -> axum::Router {
    let project = project();
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let authenticator = CaseworkAuthenticator::new(
        &project,
        oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]),
        keys,
        HumanIdentityConfig::default(),
    );
    let service = CaseworkService::new(unconnected_store(root), project.clone(), [])
        .expect("a service with no providers");
    router_with_recorder(
        HttpState {
            service,
            authenticator: Arc::new(authenticator),
            project: Arc::new(project),
        },
        recorder,
    )
}

const KEPT_HEADERS: [&str; 5] = [
    "content-type",
    "www-authenticate",
    "retry-after",
    "cache-control",
    "x-content-type-options",
];

async fn observe(app: &axum::Router, case: &Case) -> Value {
    let mut request = Request::builder().method(case.method).uri(&case.path);
    for (name, value) in &case.headers {
        request = request.header(*name, value);
    }
    let response: Response<Body> = app
        .clone()
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status().as_u16();
    let mut headers = Map::new();
    for name in KEPT_HEADERS {
        if let Some(value) = response.headers().get(name) {
            headers.insert(
                name.to_owned(),
                json!(value.to_str().expect("a printable header")),
            );
        }
    }
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let mut body: Value = serde_json::from_slice(&bytes).expect("a JSON problem body");
    body.as_object_mut()
        .expect("a problem object")
        .remove("traceId")
        .expect("every problem carries a traceId");
    json!({"name": case.name, "status": status, "headers": headers, "body": body})
}

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/refusal_responses.json")
}

#[tokio::test]
async fn authentication_and_profile_refusals_match_the_checked_in_answers() {
    let idp = MockIdp::start().await;
    let mut observed = Vec::new();
    let cases = cases(&idp);
    let tokens: Vec<String> = cases
        .iter()
        .flat_map(|case| case.headers.iter().map(|(_, value)| value.clone()))
        .collect();
    for case in &cases {
        // A recorder per case keeps each log line inside its check's budget
        // of five lines a minute, however many cases share a check.
        let root = tempfile::tempdir().expect("temporary directory");
        let recorder = Arc::new(RefusalRecorder::new("casework").expect("the casework recorder"));
        let app = app(&idp, root.path(), Arc::clone(&recorder));
        let logs = CapturedDiagnosticLogs::default();
        observed.push(observe(&app, case).with_subscriber(logs.subscriber()).await);
        assert_eq!(
            recorder.counter().get(&[case.check]),
            Some(1),
            "{} counts once under {}",
            case.name,
            case.check
        );
        let counted: u64 = FailedCheck::ALL
            .iter()
            .map(|check| recorder.counter().get(&[check.as_str()]).unwrap_or(0))
            .sum();
        assert_eq!(counted, 1, "{} counts under no other check", case.name);
        assert_one_value_free_line(case, &logs, &tokens);
    }
    let root = tempfile::tempdir().expect("temporary directory");
    let recorder = Arc::new(RefusalRecorder::new("casework").expect("the casework recorder"));
    let app = app(&idp, root.path(), Arc::clone(&recorder));
    assert_absence_is_not_counted(&app, &recorder).await;
    idp.stop().await;
    let observed = Value::Array(observed);
    let rendered = format!("{}\n", serde_json::to_string_pretty(&observed).unwrap());
    if std::env::var_os("REGISTRY_UPDATE_GOLDEN").is_some() {
        std::fs::write(golden_path(), rendered).expect("write the golden file");
        return;
    }
    let expected = std::fs::read_to_string(golden_path()).expect(
        "tests/golden/refusal_responses.json is missing; run once with REGISTRY_UPDATE_GOLDEN=1",
    );
    assert_eq!(
        rendered, expected,
        "a refusal answer changed; if the change is intended, rerun with REGISTRY_UPDATE_GOLDEN=1 and review the diff"
    );
}

/// A plain absence conceals nothing, so it is neither counted nor logged as a
/// refusal. The task grant key set route is unauthenticated and answers 404
/// when task grants are not configured.
async fn assert_absence_is_not_counted(app: &axum::Router, recorder: &RefusalRecorder) {
    let logs = CapturedDiagnosticLogs::default();
    let observed = observe(
        app,
        &case(
            "jwks-without-task-grants",
            "visibility",
            "GET",
            "/.well-known/jwks.json",
            vec![],
        ),
    )
    .with_subscriber(logs.subscriber())
    .await;
    assert_eq!(observed["status"], 404);
    assert_eq!(observed["body"]["code"], "request.not-found");
    let counted: u64 = FailedCheck::ALL
        .iter()
        .map(|check| recorder.counter().get(&[check.as_str()]).unwrap_or(0))
        .sum();
    assert_eq!(counted, 0, "an absence records no refusal");
    assert_eq!(logs.text(), "", "an absence writes no refusal line");
}

/// The one line a refusal wrote names the check, carries a trace id, and
/// holds no credential, claim or profile a caller sent.
fn assert_one_value_free_line(case: &Case, logs: &CapturedDiagnosticLogs, tokens: &[String]) {
    let text = logs.text();
    let lines: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("a JSON log line"))
        .collect();
    assert_eq!(lines.len(), 1, "{}: {text}", case.name);
    let fields = lines[0]["fields"].as_object().expect("fields");
    assert_eq!(fields["message"], "request refused", "{}", case.name);
    assert_eq!(fields["decision"], "refused", "{}", case.name);
    assert_eq!(fields["failed_check"], case.check, "{}", case.name);
    assert_eq!(fields["suppressed"], 0, "{}", case.name);
    assert_eq!(
        fields["trace_id"].as_str().map(str::len),
        Some(32),
        "{}",
        case.name
    );
    if case.check == "scope" {
        // A scope refusal names what the operator declared, never the scopes
        // the token held.
        assert_eq!(fields["scope_claim"], "scope", "{}", case.name);
        assert!(
            fields["required_scope"].is_string(),
            "{}: the line names the scope the operation needs",
            case.name
        );
        assert!(!text.contains(HELD_CANARY_SCOPE), "{}: {text}", case.name);
        if case.name == "scope-missing" {
            assert_eq!(fields["required_scope"], "casework:staff", "{}", case.name);
            assert_eq!(fields["access_profile"], "staff", "{}", case.name);
        }
    }
    for name in fields.keys() {
        assert!(
            [
                "message",
                "decision",
                "failed_check",
                "suppressed",
                "trace_id",
                "remedy",
                "scope_claim",
                "required_scope",
                "access_profile"
            ]
            .contains(&name.as_str()),
            "{}: unexpected field {name}",
            case.name
        );
    }
    // The profile id the operator declared is also a header value the caller
    // sent, so the line may name it. Nothing else the caller sent may appear.
    let declared_profile = fields.get("access_profile").and_then(Value::as_str);
    for secret in tokens.iter().chain([&PRINCIPAL.to_owned()]) {
        if Some(secret.as_str()) == declared_profile {
            continue;
        }
        assert!(!text.contains(secret.as_str()), "{}: {secret}", case.name);
    }
}
