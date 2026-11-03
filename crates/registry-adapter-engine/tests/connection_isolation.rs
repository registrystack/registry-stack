//! Named Evidence connections share physical state only by authored name.

use registry_adapter_core::{AdapterEndpointBindings, AdapterPack, EvidenceConnectionPolicy};
use registry_adapter_engine::{
    artifacts::PackArtifactBytes,
    evidence::{
        compile_evidence, EvidenceAcquisitionIntent, EvidenceCompileInputs, EvidenceHookFuture,
        EvidenceHostHooks, EvidenceLimits, EvidenceLookup, EvidenceProgram,
        EvidenceRuntimeBindings,
    },
};
use registry_platform_config::{sha256_uri, SecretProvider, SecretResolver};
use serde_json::json;
use std::{collections::BTreeMap, io, path::Path, sync::Arc, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
    task::JoinHandle,
    time::timeout,
};

const CLIENT_A: &str = "connection-a-client-canary";
const CLIENT_B: &str = "connection-b-client-canary";
const SECRET_A: &str = "connection-a-secret-canary";
const SECRET_B: &str = "connection-b-secret-canary";
const SHARED_CLIENT: &str = "shared-client-canary";
const SHARED_SECRET: &str = "shared-secret-canary";

struct Hooks;

impl EvidenceHostHooks for Hooks {
    fn before_acquisition<'a>(
        &'a self,
        _intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

struct ObservedRequest {
    path: String,
    headers: BTreeMap<String, String>,
    form: BTreeMap<String, String>,
}

struct LoopbackSource {
    origin: String,
    requests: mpsc::UnboundedReceiver<ObservedRequest>,
    data_releases: Arc<Semaphore>,
    accept_task: JoinHandle<()>,
}

impl LoopbackSource {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback source binds");
        let origin = format!(
            "http://{}",
            listener.local_addr().expect("loopback address")
        );
        let (requests_tx, requests) = mpsc::unbounded_channel();
        let data_releases = Arc::new(Semaphore::new(0));
        let releases = Arc::clone(&data_releases);
        let accept_task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("loopback accept");
                let tx = requests_tx.clone();
                let releases = Arc::clone(&releases);
                tokio::spawn(async move {
                    serve_request(stream, tx, releases)
                        .await
                        .expect("loopback request is served");
                });
            }
        });
        Self {
            origin,
            requests,
            data_releases,
            accept_task,
        }
    }

    fn token_endpoint(&self) -> String {
        format!("{}/token", self.origin)
    }

    fn release_data(&self, count: usize) {
        self.data_releases.add_permits(count);
    }

    async fn next_request(&mut self) -> ObservedRequest {
        timeout(Duration::from_secs(2), self.requests.recv())
            .await
            .expect("the bounded loopback request arrives")
            .expect("the loopback request channel remains open")
    }
}

impl Drop for LoopbackSource {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

async fn serve_request(
    mut stream: TcpStream,
    requests: mpsc::UnboundedSender<ObservedRequest>,
    data_releases: Arc<Semaphore>,
) -> io::Result<()> {
    let request = read_request(&mut stream).await?;
    let is_token = request.path == "/token";
    let client_id = request.form.get("client_id").cloned();
    requests.send(request).map_err(|_| {
        io::Error::new(io::ErrorKind::BrokenPipe, "request observer is unavailable")
    })?;

    let response = if is_token {
        let client_id = client_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "token request omitted client id",
            )
        })?;
        json!({
            "access_token": format!("token-for-{client_id}"),
            "token_type": "Bearer",
            "expires_in": 300
        })
    } else {
        let permit = data_releases.acquire().await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "data release gate is unavailable",
            )
        })?;
        drop(permit);
        json!({"lookup": "matched", "facts": {"id": "synthetic-record"}})
    };
    let body = serde_json::to_vec(&response).expect("synthetic response serializes");
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await
}

async fn read_request(stream: &mut TcpStream) -> io::Result<ObservedRequest> {
    const MAXIMUM_REQUEST_BYTES: usize = 32 * 1024;
    let mut bytes = Vec::new();
    let header_end = loop {
        if bytes.len() >= MAXIMUM_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic request exceeds its bound",
            ));
        }
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "synthetic request ended before its headers",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers_text = std::str::from_utf8(&bytes[..header_end]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic headers are not UTF-8",
        )
    })?;
    let mut lines = headers_text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic request line is absent",
        )
    })?;
    let mut request_parts = request_line.split_whitespace();
    let _method = request_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "synthetic method is absent"))?;
    let path = request_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "synthetic path is absent"))?
        .to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "synthetic header is malformed")
        })?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .map_or(Ok(0), |value| value.parse::<usize>())
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic content length is malformed",
            )
        })?;
    if header_end + content_length > MAXIMUM_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic request body exceeds its bound",
        ));
    }
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "synthetic request body is incomplete",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let form = url::form_urlencoded::parse(&bytes[header_end..header_end + content_length])
        .into_owned()
        .collect();
    Ok(ObservedRequest {
        path,
        headers,
        form,
    })
}

fn write_secret(root: &Path, name: &str, value: &str) {
    let path = root.join(name);
    std::fs::write(&path, value.as_bytes()).expect("synthetic secret is written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("synthetic secret is owner-only");
    }
}

fn secret_root(entries: &[(&str, &str)]) -> TempDir {
    let root = tempfile::tempdir().expect("synthetic secret root");
    for (name, value) in entries {
        write_secret(root.path(), name, value);
    }
    root
}

fn program(
    connection_id: &str,
    origin: &str,
    token_endpoint: &str,
    secret_root: &Path,
    client_id_ref: &str,
    client_secret_ref: &str,
) -> EvidenceProgram {
    let input_schema = serde_json::to_vec(&json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {}
    }))
    .expect("input schema serializes");
    let facts_schema = serde_json::to_vec(&json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id"],
        "properties": {"id": {"type": "string"}}
    }))
    .expect("facts schema serializes");
    let pack: AdapterPack = serde_json::from_value(json!({
        "id": "connection-isolation",
        "version": "1",
        "testedVersions": [],
        "endpoints": [{
            "id": "register",
            "component": "http",
            "authentication": {"type": "oauth2-client-credentials"},
            "attemptTimeoutMilliseconds": 2_000,
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
            "steps": [{
                "to": {
                    "uri": "http:register",
                    "parameters": {"httpMethod": "GET", "path": "/lookup"}
                }
            }]
        }]
    }))
    .expect("synthetic pack parses");
    let bindings: AdapterEndpointBindings = serde_json::from_value(json!({
        "id": connection_id,
        "endpoints": [{
            "endpoint": "register",
            "baseUrl": origin,
            "credential": {
                "type": "oauth2-client-credentials",
                "tokenEndpoint": token_endpoint,
                "clientIdRef": client_id_ref,
                "clientSecretRef": client_secret_ref,
                "scope": "records.read",
                "credentialPlacement": "form-body",
                "maximumCacheSeconds": 300
            },
            "maximumConcurrency": 1
        }],
        "allowedPrivateCidrs": []
    }))
    .expect("synthetic runtime binding parses");
    let connection: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint": "register",
        "baseUrl": origin,
        "clientIdentity": "forbidden",
        "authentication": {
            "type": "oauth2-client-credentials",
            "tokenEndpoint": token_endpoint,
            "scope": "records.read",
            "credentialPlacement": "form-body"
        }
    }))
    .expect("reviewed connection policy parses");
    let resolver = SecretResolver::new([SecretProvider::File], secret_root)
        .expect("synthetic resolver starts");
    let runtime = EvidenceRuntimeBindings::new(bindings, resolver);
    let artifacts = PackArtifactBytes::new([
        ("schemas/inputs.json".to_owned(), input_schema),
        ("schemas/facts.json".to_owned(), facts_schema),
    ]);
    compile_evidence(&EvidenceCompileInputs {
        pack: &pack,
        route: "lookup",
        runtime: &runtime,
        connection_id: Some(connection_id),
        connection: std::slice::from_ref(&connection),
        pack_artifacts: &artifacts,
        limits: EvidenceLimits::default(),
    })
    .expect("synthetic Evidence program compiles")
}

async fn execute(program: Arc<EvidenceProgram>) -> EvidenceLookup {
    let acquisition = program
        .begin_acquisition(Arc::new(Hooks))
        .await
        .expect("acquisition starts");
    program
        .execute(&acquisition, json!({}))
        .await
        .expect("lookup succeeds")
}

fn assert_token_request(request: &ObservedRequest, client_id: &str, client_secret: &str) {
    assert_eq!(request.path, "/token");
    assert!(
        request
            .form
            .get("client_id")
            .is_some_and(|value| value == client_id),
        "the named connection used a different client id"
    );
    assert!(
        request
            .form
            .get("client_secret")
            .is_some_and(|value| value == client_secret),
        "the named connection used a different client secret"
    );
}

#[tokio::test]
async fn different_named_connections_use_their_own_oauth_credentials() {
    let mut source = LoopbackSource::start().await;
    source.release_data(2);
    let secrets = secret_root(&[
        ("client-a", CLIENT_A),
        ("secret-a", SECRET_A),
        ("client-b", CLIENT_B),
        ("secret-b", SECRET_B),
    ]);
    let token_endpoint = source.token_endpoint();
    let first = Arc::new(program(
        "connection-a",
        &source.origin,
        &token_endpoint,
        secrets.path(),
        "secret:file/client-a",
        "secret:file/secret-a",
    ));
    let second = Arc::new(program(
        "connection-b",
        &source.origin,
        &token_endpoint,
        secrets.path(),
        "secret:file/client-b",
        "secret:file/secret-b",
    ));

    first
        .credentials_ready()
        .await
        .expect("first connection credential is ready");
    assert_token_request(&source.next_request().await, CLIENT_A, SECRET_A);
    second
        .credentials_ready()
        .await
        .expect("second connection credential is ready");
    assert_token_request(&source.next_request().await, CLIENT_B, SECRET_B);

    assert_eq!(
        execute(Arc::clone(&first)).await,
        EvidenceLookup::Matched {
            facts: json!({"id": "synthetic-record"})
        }
    );
    let first_data = source.next_request().await;
    assert_eq!(first_data.path, "/lookup");
    assert!(
        first_data
            .headers
            .get("authorization")
            .is_some_and(|value| value == &format!("Bearer token-for-{CLIENT_A}")),
        "the first connection sent another connection's credential"
    );
    assert_eq!(
        execute(Arc::clone(&second)).await,
        EvidenceLookup::Matched {
            facts: json!({"id": "synthetic-record"})
        }
    );
    let second_data = source.next_request().await;
    assert_eq!(second_data.path, "/lookup");
    assert!(
        second_data
            .headers
            .get("authorization")
            .is_some_and(|value| value == &format!("Bearer token-for-{CLIENT_B}")),
        "the second connection sent another connection's credential"
    );
}

#[tokio::test]
async fn different_named_connections_with_identical_material_do_not_share_cache_or_admission() {
    let mut source = LoopbackSource::start().await;
    let secrets = secret_root(&[
        ("shared-client", SHARED_CLIENT),
        ("shared-secret", SHARED_SECRET),
    ]);
    let token_endpoint = source.token_endpoint();
    let first = Arc::new(program(
        "connection-a",
        &source.origin,
        &token_endpoint,
        secrets.path(),
        "secret:file/shared-client",
        "secret:file/shared-secret",
    ));
    let second = Arc::new(program(
        "connection-b",
        &source.origin,
        &token_endpoint,
        secrets.path(),
        "secret:file/shared-client",
        "secret:file/shared-secret",
    ));

    first
        .credentials_ready()
        .await
        .expect("first connection credential is ready");
    assert_token_request(&source.next_request().await, SHARED_CLIENT, SHARED_SECRET);
    second
        .credentials_ready()
        .await
        .expect("second connection credential is independently ready");
    assert_token_request(&source.next_request().await, SHARED_CLIENT, SHARED_SECRET);

    let first_execution = tokio::spawn(execute(Arc::clone(&first)));
    let first_data = source.next_request().await;
    assert_eq!(first_data.path, "/lookup");

    let second_execution = tokio::spawn(execute(Arc::clone(&second)));
    let second_data = source.next_request().await;
    assert_eq!(second_data.path, "/lookup");
    assert!(
        !first_execution.is_finished() && !second_execution.is_finished(),
        "both data responses remain held while independent admission is observed"
    );

    source.release_data(2);
    for execution in [first_execution, second_execution] {
        assert_eq!(
            timeout(Duration::from_secs(2), execution)
                .await
                .expect("the released lookup completes")
                .expect("the lookup task remains healthy"),
            EvidenceLookup::Matched {
                facts: json!({"id": "synthetic-record"})
            }
        );
    }
}
