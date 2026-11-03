//! Evidence host regressions for named OAuth connection sharing and restart.

use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use registry_adapter_core::EvidenceConnectionPolicy;
use registry_adapter_engine::evidence::{
    EvidenceAcquisitionIntent, EvidenceHookFuture, EvidenceHostHooks, EvidenceLimits,
    EvidenceRuntimeBindings, EvidenceSendIntent,
};
use registry_evidence::bundle::{evidence_package_limits, Bundle};
use registry_evidence::model::LookupResult;
use registry_evidence::pack_source::{PackSourceError, PackSourceExecutor};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
use tempfile::TempDir;
use tokio::time::{sleep, timeout};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CLIENT_ID: &str = "synthetic-named-client";
const PREDECESSOR_SECRET: &str = "synthetic-predecessor-secret";
const SUCCESSOR_SECRET: &str = "synthetic-successor-secret";
const PREDECESSOR_TOKEN: &str = "synthetic-predecessor-token";
const SUCCESSOR_TOKEN: &str = "synthetic-successor-token";
const TRACKING_ID: &str = "TRACKING-SYNTHETIC-NAMED-001";

fn reference_bundle() -> Bundle {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle",
    );
    let verified = registry_platform_config::verify_package(
        &root,
        &evidence_package_limits(),
        "evidence named-connection test",
    )
    .expect("the maintained OpenCRVS Evidence package verifies");
    Bundle::load_as_found(&root, &verified).expect("the maintained OpenCRVS Evidence package loads")
}

fn write_secret(root: &TempDir, name: &str, value: &str) {
    let secret = root.path().join(name);
    fs::write(&secret, value).expect("write synthetic file secret");
    #[cfg(unix)]
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))
        .expect("protect synthetic file secret");
}

fn resolver(root: &TempDir) -> Arc<SecretResolver> {
    SecretResolver::new([SecretProvider::File], root.path())
        .map(Arc::new)
        .expect("file secret resolver")
}

fn runtime_bindings(
    server: &MockServer,
    secrets: Arc<SecretResolver>,
    maximum_concurrency: u64,
) -> EvidenceRuntimeBindings {
    EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":"opencrvs",
            "endpoints":[{
                "endpoint":"events",
                "baseUrl":server.uri(),
                "credential":{
                    "type":"oauth2-client-credentials",
                    "tokenEndpoint":format!("{}/token", server.uri()),
                    "clientIdRef":"secret:file/client-id",
                    "clientSecretRef":"secret:file/client-secret",
                    "scope":"recordsearch",
                    "credentialPlacement":"form-body",
                    "maximumCacheSeconds":300,
                    "assumedLifetimeSeconds":300
                },
                "maximumConcurrency":maximum_concurrency
            }],
            "allowedPrivateCidrs":[]
        }))
        .expect("named OpenCRVS runtime binding"),
        secrets,
        BTreeMap::new(),
    )
}

fn connection_policy(server: &MockServer) -> EvidenceConnectionPolicy {
    serde_json::from_value(json!({
        "endpoint":"events",
        "baseUrl":server.uri(),
        "clientIdentity":"forbidden",
        "authentication":{
            "type":"oauth2-client-credentials",
            "tokenEndpoint":format!("{}/token", server.uri()),
            "scope":"recordsearch",
            "credentialPlacement":"form-body"
        }
    }))
    .expect("reviewed named-connection policy")
}

fn executors(
    bundle: &Bundle,
    server: &MockServer,
    secrets: Arc<SecretResolver>,
    maximum_concurrency: u64,
) -> (Arc<PackSourceExecutor>, Arc<PackSourceExecutor>) {
    let runtime = runtime_bindings(server, secrets, maximum_concurrency);
    let policy = connection_policy(server);
    let compile = |source_id: &str| {
        let source = bundle
            .config
            .sources
            .get(source_id)
            .expect("maintained source exists");
        Arc::new(
            PackSourceExecutor::compile(
                source,
                bundle
                    .source_pack(source_id)
                    .expect("maintained source pack closure"),
                &runtime,
                std::slice::from_ref(&policy),
                EvidenceLimits::default(),
            )
            .expect("named source compiles through the Evidence pack host"),
        )
    };
    (
        compile("registered-birth-date"),
        compile("registered-birth-parents"),
    )
}

fn source_response() -> serde_json::Value {
    json!({
        "total":1,
        "results":[{
            "type":"birth",
            "status":"REGISTERED",
            "trackingId":TRACKING_ID,
            "dateOfEvent":"2000-01-01",
            "declaration":{
                "mother.personReference":"PERSON-SYNTHETIC-A",
                "unmapped.private":"must-not-leave-source"
            }
        }]
    })
}

fn inputs() -> serde_json::Value {
    json!({"trackingId":TRACKING_ID})
}

fn assert_private_lookup(result: &Result<LookupResult, PackSourceError>) {
    let Ok(LookupResult::Match(facts)) = result else {
        panic!("the maintained source must return one closed match");
    };
    let rendered = serde_json::to_string(facts).expect("matched facts serialize");
    for private in [
        "must-not-leave-source",
        PREDECESSOR_SECRET,
        SUCCESSOR_SECRET,
        PREDECESSOR_TOKEN,
        SUCCESSOR_TOKEN,
    ] {
        assert!(
            !rendered.contains(private),
            "private source and credential material must not enter Evidence facts"
        );
    }
}

#[derive(Default)]
struct OrderedHooks {
    intent_recorded: AtomicBool,
    credentials: AtomicUsize,
}

impl EvidenceHostHooks for OrderedHooks {
    fn before_acquisition<'a>(
        &'a self,
        intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        assert_eq!(intent.pack, "opencrvs-events");
        assert!(matches!(
            intent.route.as_str(),
            "evidence-birth-date" | "evidence-birth-parents"
        ));
        self.intent_recorded.store(true, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn before_credentials<'a>(&'a self, _: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
        assert!(
            self.intent_recorded.load(Ordering::SeqCst),
            "durable acquisition intent must precede credentials and source effects"
        );
        self.credentials.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

async fn execute(
    executor: Arc<PackSourceExecutor>,
) -> (Result<LookupResult, PackSourceError>, Arc<OrderedHooks>) {
    let hooks = Arc::new(OrderedHooks::default());
    let result = executor.execute(inputs(), Utc::now(), hooks.clone()).await;
    (result, hooks)
}

fn request_count(requests: &[wiremock::Request], request_path: &str) -> usize {
    requests
        .iter()
        .filter(|request| request.url.path() == request_path)
        .count()
}

async fn wait_for_request(server: &MockServer, request_path: &str) {
    timeout(Duration::from_secs(3), async {
        loop {
            if server
                .received_requests()
                .await
                .expect("request journal is available")
                .iter()
                .any(|request| request.url.path() == request_path)
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("request {request_path} did not arrive"));
}

async fn mount_token(
    server: &MockServer,
    secret: &str,
    token: &str,
    delay: Duration,
    expected: u64,
) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains(format!("client_id={CLIENT_ID}")))
        .and(body_string_contains(format!("client_secret={secret}")))
        .and(body_string_contains("scope=recordsearch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(delay)
                .set_body_json(json!({
                    "access_token":token,
                    "token_type":"Bearer",
                    "expires_in":300
                })),
        )
        .expect(expected)
        .mount(server)
        .await;
}

async fn mount_data(server: &MockServer, token: &str, delay: Duration, expected: u64) {
    Mock::given(method("POST"))
        .and(path("/events/search"))
        .and(header("authorization", format!("Bearer {token}")))
        .and(header("accept", "application/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(delay)
                .set_body_json(source_response()),
        )
        .expect(expected)
        .mount(server)
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn named_oauth_rotation_preserves_live_cache_and_restart_reads_the_rotated_secret() {
    let server = MockServer::start().await;
    mount_token(
        &server,
        PREDECESSOR_SECRET,
        PREDECESSOR_TOKEN,
        Duration::from_millis(100),
        1,
    )
    .await;
    mount_token(
        &server,
        SUCCESSOR_SECRET,
        SUCCESSOR_TOKEN,
        Duration::ZERO,
        1,
    )
    .await;
    mount_data(&server, PREDECESSOR_TOKEN, Duration::ZERO, 3).await;
    mount_data(&server, SUCCESSOR_TOKEN, Duration::ZERO, 1).await;

    let secret_root = tempfile::tempdir().expect("temporary secret root");
    write_secret(&secret_root, "client-id", CLIENT_ID);
    write_secret(&secret_root, "client-secret", PREDECESSOR_SECRET);
    let bundle = reference_bundle();
    let (birth_date, birth_parents) = executors(&bundle, &server, resolver(&secret_root), 2);

    let (first, second) = tokio::join!(execute(birth_date.clone()), execute(birth_parents));
    assert_private_lookup(&first.0);
    assert_private_lookup(&second.0);
    assert_eq!(first.1.credentials.load(Ordering::SeqCst), 1);
    assert_eq!(second.1.credentials.load(Ordering::SeqCst), 1);
    assert_eq!(
        request_count(&server.received_requests().await.unwrap(), "/token"),
        1,
        "two logical Sources on one named physical connection share one refresh"
    );

    write_secret(&secret_root, "client-secret", SUCCESSOR_SECRET);
    let (still_live, live_hooks) = execute(birth_date).await;
    assert_private_lookup(&still_live);
    assert_eq!(live_hooks.credentials.load(Ordering::SeqCst), 1);
    assert_eq!(
        request_count(&server.received_requests().await.unwrap(), "/token"),
        1,
        "file rotation must not invalidate an unexpired live cache"
    );

    let (restarted, _) = executors(&bundle, &server, resolver(&secret_root), 2);
    let (after_restart, restart_hooks) = execute(restarted).await;
    assert_private_lookup(&after_restart);
    assert_eq!(restart_hooks.credentials.load(Ordering::SeqCst), 1);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(request_count(&requests, "/token"), 2);
    assert_eq!(request_count(&requests, "/events/search"), 4);
    for request in requests
        .iter()
        .filter(|request| request.url.path() == "/events/search")
    {
        assert!(!request
            .body
            .windows(PREDECESSOR_SECRET.len())
            .any(|part| { part == PREDECESSOR_SECRET.as_bytes() }));
        assert!(!request
            .body
            .windows(SUCCESSOR_SECRET.len())
            .any(|part| { part == SUCCESSOR_SECRET.as_bytes() }));
        for header_value in request.headers.values() {
            assert!(!header_value
                .as_bytes()
                .windows(PREDECESSOR_SECRET.len())
                .any(|part| { part == PREDECESSOR_SECRET.as_bytes() }));
            assert!(!header_value
                .as_bytes()
                .windows(SUCCESSOR_SECRET.len())
                .any(|part| { part == SUCCESSOR_SECRET.as_bytes() }));
        }
    }
    assert!(requests
        .iter()
        .all(|request| matches!(request.url.path(), "/token" | "/events/search")));
    server.verify().await;
}

#[cfg(unix)]
#[tokio::test]
async fn readiness_joins_refresh_without_data_admission_and_stalled_admission_sheds() {
    let bundle = reference_bundle();
    let secret_root = tempfile::tempdir().expect("temporary secret root");
    write_secret(&secret_root, "client-id", CLIENT_ID);
    write_secret(&secret_root, "client-secret", PREDECESSOR_SECRET);

    let sharing_server = MockServer::start().await;
    mount_token(
        &sharing_server,
        PREDECESSOR_SECRET,
        PREDECESSOR_TOKEN,
        Duration::from_millis(300),
        1,
    )
    .await;
    mount_data(
        &sharing_server,
        PREDECESSOR_TOKEN,
        Duration::from_secs(2),
        1,
    )
    .await;
    let (data_executor, readiness_executor) =
        executors(&bundle, &sharing_server, resolver(&secret_root), 1);
    let data_task = tokio::spawn(execute(data_executor));
    wait_for_request(&sharing_server, "/token").await;
    // Operator readiness is the explicit no-audit path. It may bootstrap a
    // credential, but it must not acquire the data semaphore or send data.
    let readiness_task = tokio::spawn(async move { readiness_executor.credentials_ready().await });
    wait_for_request(&sharing_server, "/events/search").await;
    timeout(Duration::from_millis(500), readiness_task)
        .await
        .expect("readiness must not wait for the occupied data slot")
        .expect("readiness task joins")
        .expect("readiness uses the concurrently filled shared cache");
    let (lookup, hooks) = data_task.await.expect("data task joins");
    assert_private_lookup(&lookup);
    assert_eq!(hooks.credentials.load(Ordering::SeqCst), 1);
    let requests = sharing_server.received_requests().await.unwrap();
    assert_eq!(request_count(&requests, "/token"), 1);
    assert_eq!(request_count(&requests, "/events/search"), 1);
    sharing_server.verify().await;

    let stalled_server = MockServer::start().await;
    mount_token(
        &stalled_server,
        PREDECESSOR_SECRET,
        PREDECESSOR_TOKEN,
        Duration::from_secs(15),
        1,
    )
    .await;
    let (refreshing, shed_waiter) = executors(&bundle, &stalled_server, resolver(&secret_root), 1);
    let stalled_refresh = tokio::spawn(async move { refreshing.credentials_ready().await });
    wait_for_request(&stalled_server, "/token").await;
    let error = timeout(Duration::from_secs(7), shed_waiter.credentials_ready())
        .await
        .expect("the token-cache admission bound is finite")
        .expect_err("a waiter behind a stalled refresh is shed");
    assert_eq!(error, PackSourceError::Credential);
    assert_eq!(error.to_string(), "the source credential is unavailable");
    assert_eq!(format!("{error:?}"), "Credential");
    assert!(!error.to_string().contains(PREDECESSOR_SECRET));
    assert!(!error.to_string().contains(PREDECESSOR_TOKEN));
    stalled_refresh.abort();
    assert!(stalled_refresh.await.unwrap_err().is_cancelled());
    let requests = stalled_server.received_requests().await.unwrap();
    assert_eq!(request_count(&requests, "/token"), 1);
    assert_eq!(
        request_count(&requests, "/events/search"),
        0,
        "operator readiness may resolve credentials but never sends source data"
    );
    stalled_server.verify().await;
}
