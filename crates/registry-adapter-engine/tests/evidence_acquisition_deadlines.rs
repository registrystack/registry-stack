//! Evidence acquisitions keep one absolute deadline across physical admission,
//! reviewed retries, and reviewed page loops.

use registry_adapter_core::{
    AdapterEndpointBindings, AdapterPack, ErrorClass, EvidenceConnectionPolicy,
};
use registry_adapter_engine::{
    artifacts::PackArtifactBytes,
    evidence::{
        compile_evidence, EvidenceAcquisitionIntent, EvidenceCompileInputs, EvidenceExecutionError,
        EvidenceHookFuture, EvidenceHostHooks, EvidenceLimits, EvidenceLookup, EvidenceProgram,
        EvidenceReadinessError, EvidenceRuntimeBindings, EvidenceSendIntent,
    },
};
use registry_platform_config::{sha256_uri, SecretProvider, SecretResolver};
use serde_json::{json, Value};
use std::{
    io,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
    task::JoinHandle,
    time::timeout,
};

const CLIENT_ID_CANARY: &str = "deadline-client-canary";
const CLIENT_SECRET_CANARY: &str = "deadline-secret-canary";
const ACCESS_TOKEN_CANARY: &str = "deadline-token-canary";
const STATIC_AUTHORIZATION_CANARY: &str = "deadline-static-token-canary";
const CONNECTION_ID: &str = "deadline-proof-connection";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HookEvent {
    Acquisition,
    BeforeCredentials(usize),
}

struct ObservedHooks {
    acquisitions: AtomicUsize,
    before_credentials: AtomicUsize,
    stall_before_credentials: Option<usize>,
    events: mpsc::UnboundedSender<HookEvent>,
}

impl ObservedHooks {
    fn new(
        stall_before_credentials: Option<usize>,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<HookEvent>) {
        let (events, receiver) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                acquisitions: AtomicUsize::new(0),
                before_credentials: AtomicUsize::new(0),
                stall_before_credentials,
                events,
            }),
            receiver,
        )
    }

    async fn wait_for_before_credentials(
        receiver: &mut mpsc::UnboundedReceiver<HookEvent>,
        expected: usize,
    ) {
        timeout(Duration::from_secs(2), async {
            loop {
                match receiver.recv().await {
                    Some(HookEvent::BeforeCredentials(current)) if current == expected => return,
                    Some(_) => {}
                    None => panic!("the hook observer closed before the expected event"),
                }
            }
        })
        .await
        .expect("the expected pre-credential hook is reached");
    }
}

impl EvidenceHostHooks for ObservedHooks {
    fn before_acquisition<'a>(
        &'a self,
        _intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        self.events
            .send(HookEvent::Acquisition)
            .expect("the hook observer remains available");
        Box::pin(async { Ok(()) })
    }

    fn before_credentials<'a>(&'a self, _intent: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
        let current = self.before_credentials.fetch_add(1, Ordering::SeqCst) + 1;
        self.events
            .send(HookEvent::BeforeCredentials(current))
            .expect("the hook observer remains available");
        if self.stall_before_credentials == Some(current) {
            return Box::pin(std::future::pending());
        }
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClockInhibitorExit {
    Released,
    WallTimeout,
    TestEnded,
}

/// Keep Tokio's paused clock stationary while real filesystem and socket work
/// reaches the proof barrier. Tokio explicitly inhibits paused-clock
/// auto-advance while a blocking task is live; the wall timeout ensures a
/// failed barrier cannot leave the test or the blocking pool stuck.
struct PausedClockInhibitor {
    release: Option<std::sync::mpsc::Sender<()>>,
    blocker: Option<JoinHandle<ClockInhibitorExit>>,
}

impl PausedClockInhibitor {
    fn start() -> Self {
        let (release, wait_for_release) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            match wait_for_release.recv_timeout(Duration::from_secs(5)) {
                Ok(()) => ClockInhibitorExit::Released,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => ClockInhibitorExit::WallTimeout,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    ClockInhibitorExit::TestEnded
                }
            }
        });
        Self {
            release: Some(release),
            blocker: Some(blocker),
        }
    }

    async fn release(mut self) {
        self.release
            .take()
            .expect("the paused-clock release remains available")
            .send(())
            .expect("the paused-clock blocker remains available");
        let exit = self
            .blocker
            .take()
            .expect("the paused-clock blocker remains owned")
            .await
            .expect("the paused-clock blocker remains healthy");
        assert_eq!(
            exit,
            ClockInhibitorExit::Released,
            "the proof barrier must be reached before the wall-clock failsafe"
        );
    }
}

impl Drop for PausedClockInhibitor {
    fn drop(&mut self) {
        drop(self.release.take());
    }
}

struct AbortOnDropTask<T> {
    task: Option<JoinHandle<T>>,
}

impl<T> AbortOnDropTask<T> {
    fn new(task: JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        self.task
            .as_mut()
            .expect("the execution task remains owned")
            .await
    }
}

impl<T> Drop for AbortOnDropTask<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct LoopbackSource {
    origin: String,
    token_requests: Arc<AtomicUsize>,
    data_requests: Arc<AtomicUsize>,
    data_observed: mpsc::UnboundedReceiver<String>,
    held_data_releases: Arc<Semaphore>,
    accept_task: JoinHandle<()>,
}

impl LoopbackSource {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the synthetic source binds loopback");
        let origin = format!(
            "http://{}",
            listener.local_addr().expect("the loopback address exists")
        );
        let token_requests = Arc::new(AtomicUsize::new(0));
        let data_requests = Arc::new(AtomicUsize::new(0));
        let (data_observed_tx, data_observed) = mpsc::unbounded_channel();
        let held_data_releases = Arc::new(Semaphore::new(0));
        let observed_tokens = Arc::clone(&token_requests);
        let observed_data = Arc::clone(&data_requests);
        let releases = Arc::clone(&held_data_releases);
        let accept_task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("the source accepts");
                let token_requests = Arc::clone(&observed_tokens);
                let data_requests = Arc::clone(&observed_data);
                let data_observed = data_observed_tx.clone();
                let held_data_releases = Arc::clone(&releases);
                tokio::spawn(async move {
                    serve_request(
                        stream,
                        token_requests,
                        data_requests,
                        data_observed,
                        held_data_releases,
                    )
                    .await
                    .expect("the synthetic request is served");
                });
            }
        });
        Self {
            origin,
            token_requests,
            data_requests,
            data_observed,
            held_data_releases,
            accept_task,
        }
    }

    fn token_endpoint(&self) -> String {
        format!("{}/token", self.origin)
    }

    async fn next_data_request(&mut self) -> String {
        timeout(Duration::from_secs(2), self.data_observed.recv())
            .await
            .expect("the expected data request reaches the source")
            .expect("the data observer remains available")
    }

    fn release_held_data(&self, count: usize) {
        self.held_data_releases.add_permits(count);
    }
}

impl Drop for LoopbackSource {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

async fn serve_request(
    mut stream: TcpStream,
    token_requests: Arc<AtomicUsize>,
    data_requests: Arc<AtomicUsize>,
    data_observed: mpsc::UnboundedSender<String>,
    held_data_releases: Arc<Semaphore>,
) -> io::Result<()> {
    let path = read_request_path(&mut stream).await?;
    let (status, body) = if path == "/token" {
        token_requests.fetch_add(1, Ordering::SeqCst);
        (
            200,
            json!({
                "access_token": ACCESS_TOKEN_CANARY,
                "token_type": "Bearer",
                "expires_in": 300
            }),
        )
    } else {
        data_requests.fetch_add(1, Ordering::SeqCst);
        data_observed.send(path.clone()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the data observer is unavailable",
            )
        })?;
        match path.as_str() {
            "/held" => {
                let permit = held_data_releases.acquire().await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "the data gate is unavailable")
                })?;
                drop(permit);
                (200, matched_lookup())
            }
            "/retry" => (503, json!({"busy": true})),
            "/page" => (200, matched_lookup()),
            _ => (404, json!({"missing": true})),
        }
    };
    let body = serde_json::to_vec(&body).expect("the synthetic response serializes");
    let head = format!(
        "HTTP/1.1 {status} Synthetic\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await
}

async fn read_request_path(stream: &mut TcpStream) -> io::Result<String> {
    const MAXIMUM_REQUEST_BYTES: usize = 32 * 1024;
    let mut bytes = Vec::new();
    let header_end = loop {
        if bytes.len() >= MAXIMUM_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the synthetic request exceeded its bound",
            ));
        }
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the synthetic request ended before its headers",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "headers are not UTF-8"))?;
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the request line is absent"))?;
    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the request path is absent"))?
        .to_owned();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map_or(Ok(0), |(_, value)| value.trim().parse::<usize>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid content length"))?;
    if header_end + content_length > MAXIMUM_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the synthetic request body exceeded its bound",
        ));
    }
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the synthetic request body is incomplete",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(path)
}

fn matched_lookup() -> Value {
    json!({"lookup": "matched", "facts": {"id": "synthetic-record"}})
}

fn write_secret(root: &Path, name: &str, value: &str) {
    let path = root.join(name);
    std::fs::write(&path, value.as_bytes()).expect("the synthetic secret is written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("the synthetic secret is owner-only");
    }
}

fn secret_root() -> TempDir {
    let root = tempfile::tempdir().expect("a synthetic secret root");
    write_secret(root.path(), "client-id", CLIENT_ID_CANARY);
    write_secret(root.path(), "client-secret", CLIENT_SECRET_CANARY);
    write_secret(
        root.path(),
        "authorization-token",
        STATIC_AUTHORIZATION_CANARY,
    );
    root
}

fn oauth_runtime(source: &LoopbackSource, secret_root: &Path) -> EvidenceRuntimeBindings {
    let bindings: AdapterEndpointBindings = serde_json::from_value(json!({
        "id": CONNECTION_ID,
        "endpoints": [{
            "endpoint": "register",
            "baseUrl": source.origin,
            "credential": {
                "type": "oauth2-client-credentials",
                "tokenEndpoint": source.token_endpoint(),
                "clientIdRef": "secret:file/client-id",
                "clientSecretRef": "secret:file/client-secret",
                "scope": "records.read",
                "credentialPlacement": "form-body",
                "maximumCacheSeconds": 300
            },
            "maximumConcurrency": 1
        }],
        "allowedPrivateCidrs": []
    }))
    .expect("the runtime binding parses");
    let resolver = SecretResolver::new([SecretProvider::File], secret_root)
        .expect("the synthetic resolver starts");
    EvidenceRuntimeBindings::new(bindings, resolver)
}

fn static_runtime(source: &LoopbackSource, secret_root: &Path) -> EvidenceRuntimeBindings {
    let bindings: AdapterEndpointBindings = serde_json::from_value(json!({
        "id": CONNECTION_ID,
        "endpoints": [{
            "endpoint": "register",
            "baseUrl": source.origin,
            "credential": {
                "type": "static-authorization",
                "tokenRef": "secret:file/authorization-token"
            },
            "maximumConcurrency": 1
        }],
        "allowedPrivateCidrs": []
    }))
    .expect("the static runtime binding parses");
    let resolver = SecretResolver::new([SecretProvider::File], secret_root)
        .expect("the synthetic resolver starts");
    EvidenceRuntimeBindings::new(bindings, resolver)
}

fn oauth_connection(source: &LoopbackSource) -> EvidenceConnectionPolicy {
    serde_json::from_value(json!({
        "endpoint": "register",
        "baseUrl": source.origin,
        "clientIdentity": "forbidden",
        "authentication": {
            "type": "oauth2-client-credentials",
            "tokenEndpoint": source.token_endpoint(),
            "scope": "records.read",
            "credentialPlacement": "form-body"
        }
    }))
    .expect("the reviewed connection policy parses")
}

fn static_connection(source: &LoopbackSource) -> EvidenceConnectionPolicy {
    serde_json::from_value(json!({
        "endpoint": "register",
        "baseUrl": source.origin,
        "clientIdentity": "forbidden",
        "authentication": {"type": "static-authorization"}
    }))
    .expect("the reviewed static connection policy parses")
}

fn compile_program(
    runtime: &EvidenceRuntimeBindings,
    connection: &EvidenceConnectionPolicy,
    authentication: Value,
    steps: Value,
    deadline_milliseconds: u64,
) -> EvidenceProgram {
    let input_schema = serde_json::to_vec(&json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {}
    }))
    .expect("the input schema serializes");
    let facts_schema = serde_json::to_vec(&json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id"],
        "properties": {"id": {"type": "string"}}
    }))
    .expect("the facts schema serializes");
    let pack: AdapterPack = serde_json::from_value(json!({
        "id": "acquisition-deadline-proofs",
        "version": "1",
        "testedVersions": [],
        "endpoints": [{
            "id": "register",
            "component": "http",
            "authentication": authentication,
            "attemptTimeoutMilliseconds": 5_000,
            "maximumResponseBytes": 4_096,
            "requestHeaders": [],
            "responseHeaders": [],
            "operations": [],
            "testedVersions": []
        }],
        "sourceRoutes": [{
            "id": "lookup",
            "evidence": {
                "inputsSchema": {
                    "path": "schemas/inputs.json",
                    "digest": sha256_uri(&input_schema)
                },
                "factsSchema": {
                    "path": "schemas/facts.json",
                    "digest": sha256_uri(&facts_schema)
                }
            },
            "steps": steps
        }]
    }))
    .expect("the synthetic pack parses");
    let artifacts = PackArtifactBytes::new([
        ("schemas/inputs.json".to_owned(), input_schema),
        ("schemas/facts.json".to_owned(), facts_schema),
    ]);
    compile_evidence(&EvidenceCompileInputs {
        pack: &pack,
        route: "lookup",
        runtime,
        connection_id: Some(CONNECTION_ID),
        connection: std::slice::from_ref(connection),
        pack_artifacts: &artifacts,
        limits: EvidenceLimits::try_new(4, deadline_milliseconds, 16 * 1024)
            .expect("the acquisition limits are finite"),
    })
    .expect("the reviewed Evidence program compiles")
}

fn oauth_program(
    runtime: &EvidenceRuntimeBindings,
    connection: &EvidenceConnectionPolicy,
    steps: Value,
    deadline_milliseconds: u64,
) -> EvidenceProgram {
    compile_program(
        runtime,
        connection,
        json!({"type": "oauth2-client-credentials"}),
        steps,
        deadline_milliseconds,
    )
}

fn static_program(
    runtime: &EvidenceRuntimeBindings,
    connection: &EvidenceConnectionPolicy,
    steps: Value,
    deadline_milliseconds: u64,
) -> EvidenceProgram {
    compile_program(
        runtime,
        connection,
        json!({"type": "static-authorization", "scheme": "Bearer"}),
        steps,
        deadline_milliseconds,
    )
}

fn get(path: &str) -> Value {
    json!({"to": {"uri": "http:register", "parameters": {
        "httpMethod": "GET", "path": path
    }}})
}

fn assert_budget_refusal(error: EvidenceExecutionError) {
    let rendered = error.to_string();
    assert_eq!(rendered, "the Evidence route failed");
    assert!(!rendered.contains(CLIENT_SECRET_CANARY));
    assert!(!rendered.contains(ACCESS_TOKEN_CANARY));
    assert!(!rendered.contains(STATIC_AUTHORIZATION_CANARY));
    let EvidenceExecutionError::Route(failure) = error else {
        panic!("the absolute acquisition deadline must remain a route budget refusal");
    };
    assert_eq!(failure.class, ErrorClass::BudgetExhausted);
    assert!(failure.message.is_none());
    assert!(failure.data.is_none());
    assert!(failure.auth.is_none());
    assert!(failure.code.is_none());
    assert!(failure.evidence_diagnostic.is_none());
}

#[tokio::test]
async fn saturated_named_connection_refuses_before_credentials_or_data_and_recovers() {
    let mut source = LoopbackSource::start().await;
    let secrets = secret_root();
    let runtime = static_runtime(&source, secrets.path());
    let connection = static_connection(&source);
    let long_program = Arc::new(static_program(
        &runtime,
        &connection,
        json!([get("/held")]),
        5_000,
    ));
    let short_program = Arc::new(static_program(
        &runtime,
        &connection,
        json!([get("/held")]),
        400,
    ));
    let (hooks, _hook_events) = ObservedHooks::new(None);

    let first_acquisition = long_program
        .begin_acquisition(hooks.clone())
        .await
        .expect("the first acquisition begins");
    let running_program = Arc::clone(&long_program);
    let first =
        tokio::spawn(async move { running_program.execute(&first_acquisition, json!({})).await });
    assert_eq!(source.next_data_request().await, "/held");
    assert_eq!(source.token_requests.load(Ordering::SeqCst), 0);

    write_secret(
        secrets.path(),
        "authorization-token",
        "invalid-token-with-newline\n",
    );
    let readiness = timeout(Duration::from_secs(2), long_program.credentials_ready())
        .await
        .expect("credential readiness does not wait for the held data permit")
        .expect_err("the invalid static token is refused");
    assert_eq!(
        readiness.to_string(),
        "an Evidence source credential is not ready"
    );
    assert!(!readiness.to_string().contains(STATIC_AUTHORIZATION_CANARY));
    assert!(matches!(readiness, EvidenceReadinessError::Credential));
    assert_eq!(source.data_requests.load(Ordering::SeqCst), 1);

    let second_acquisition = short_program
        .begin_acquisition(hooks.clone())
        .await
        .expect("the competing acquisition records intent");
    let second_error = timeout(
        Duration::from_secs(2),
        short_program.execute(&second_acquisition, json!({})),
    )
    .await
    .expect("the acquisition deadline bounds physical admission")
    .expect_err("the saturated connection is refused");
    assert_budget_refusal(second_error);
    assert_eq!(hooks.acquisitions.load(Ordering::SeqCst), 2);
    assert_eq!(hooks.before_credentials.load(Ordering::SeqCst), 2);
    assert_eq!(source.token_requests.load(Ordering::SeqCst), 0);
    assert_eq!(source.data_requests.load(Ordering::SeqCst), 1);

    write_secret(
        secrets.path(),
        "authorization-token",
        STATIC_AUTHORIZATION_CANARY,
    );
    assert_eq!(
        std::fs::read(secrets.path().join("authorization-token"))
            .expect("the restored static token is readable"),
        STATIC_AUTHORIZATION_CANARY.as_bytes()
    );
    source.release_held_data(1);
    assert_eq!(
        timeout(Duration::from_secs(2), first)
            .await
            .expect("the released first lookup completes")
            .expect("the first lookup task remains healthy")
            .expect("the first lookup succeeds"),
        EvidenceLookup::Matched {
            facts: json!({"id": "synthetic-record"})
        }
    );

    source.release_held_data(1);
    let reuse_acquisition = short_program
        .begin_acquisition(hooks.clone())
        .await
        .expect("a later acquisition begins");
    assert_eq!(
        timeout(
            Duration::from_secs(2),
            short_program.execute(&reuse_acquisition, json!({})),
        )
        .await
        .expect("the later lookup remains bounded")
        .expect("the named connection is reusable"),
        EvidenceLookup::Matched {
            facts: json!({"id": "synthetic-record"})
        }
    );
    assert_eq!(source.next_data_request().await, "/held");
    assert_eq!(hooks.acquisitions.load(Ordering::SeqCst), 3);
    assert_eq!(hooks.before_credentials.load(Ordering::SeqCst), 3);
    assert_eq!(source.token_requests.load(Ordering::SeqCst), 0);
    assert_eq!(source.data_requests.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn reviewed_retry_cannot_start_a_second_send_after_the_acquisition_deadline() {
    let clock = PausedClockInhibitor::start();
    let mut source = LoopbackSource::start().await;
    let secrets = secret_root();
    let runtime = oauth_runtime(&source, secrets.path());
    let connection = oauth_connection(&source);
    let program = oauth_program(
        &runtime,
        &connection,
        json!([
            {"errorHandler": {"defaultErrorHandler": {
                "redeliveryPolicy": {
                    "maximumRedeliveries": 1,
                    "retryDelaySeconds": 1
                },
                "retryWhile": {"jsonpath": "$.busy"}
            }}},
            get("/retry")
        ]),
        400,
    );
    let program = Arc::new(program);
    let (hooks, _hook_events) = ObservedHooks::new(None);
    let acquisition = program
        .begin_acquisition(hooks.clone())
        .await
        .expect("the retry acquisition begins");
    let running_program = Arc::clone(&program);
    let execution = AbortOnDropTask::new(tokio::spawn(async move {
        running_program.execute(&acquisition, json!({})).await
    }));

    assert_eq!(source.next_data_request().await, "/retry");
    clock.release().await;
    let error = timeout(Duration::from_secs(2), execution.join())
        .await
        .expect("the acquisition deadline, not the five-second attempt timeout, bounds retry")
        .expect("the retry task remains healthy")
        .expect_err("the retry cannot outlive the acquisition");
    assert_budget_refusal(error);
    assert_eq!(hooks.acquisitions.load(Ordering::SeqCst), 1);
    assert_eq!(hooks.before_credentials.load(Ordering::SeqCst), 1);
    assert_eq!(source.token_requests.load(Ordering::SeqCst), 1);
    assert_eq!(source.data_requests.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn reviewed_page_loop_cannot_resolve_credentials_or_send_after_its_deadline() {
    let clock = PausedClockInhibitor::start();
    let mut source = LoopbackSource::start().await;
    let secrets = secret_root();
    let runtime = oauth_runtime(&source, secrets.path());
    let connection = oauth_connection(&source);
    let program = Arc::new(oauth_program(
        &runtime,
        &connection,
        json!([{"loop": {
            "constant": 2,
            "maximumIterations": 2,
            "steps": [get("/page")]
        }}]),
        400,
    ));
    let (hooks, mut hook_events) = ObservedHooks::new(Some(2));
    let acquisition = program
        .begin_acquisition(hooks.clone())
        .await
        .expect("the paged acquisition begins");
    let running_program = Arc::clone(&program);
    let execution = AbortOnDropTask::new(tokio::spawn(async move {
        running_program.execute(&acquisition, json!({})).await
    }));

    assert_eq!(source.next_data_request().await, "/page");
    ObservedHooks::wait_for_before_credentials(&mut hook_events, 2).await;
    clock.release().await;
    let error = timeout(Duration::from_secs(2), execution.join())
        .await
        .expect("the page loop remains inside the acquisition deadline")
        .expect("the page-loop task remains healthy")
        .expect_err("the blocked second page is refused at the deadline");
    assert_budget_refusal(error);
    assert_eq!(hooks.acquisitions.load(Ordering::SeqCst), 1);
    assert_eq!(hooks.before_credentials.load(Ordering::SeqCst), 2);
    assert_eq!(source.token_requests.load(Ordering::SeqCst), 1);
    assert_eq!(source.data_requests.load(Ordering::SeqCst), 1);
}
