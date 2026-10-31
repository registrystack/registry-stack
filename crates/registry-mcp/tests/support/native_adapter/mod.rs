// SPDX-License-Identifier: Apache-2.0

mod source;

pub use source::{fixture_response, Reply, Source};

use registry_mcp::{config::RuntimeConfig, runtime};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use registry_platform_testing::{TestActorKind, TestAuthorizationServer, TestClient};
use registry_platform_yaml::Reader;
use rmcp::{
    model::{CallToolRequestParams, CallToolResult},
    service::RunningService,
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig, StreamableHttpClientTransport,
    },
    RoleClient, ServiceExt as _,
};
use serde_json::{json, Value};
use std::{
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::FromStr as _,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const GET_TOOL: &str = "get_facility";
pub const SEARCH_TOOL: &str = "search_facilities";
pub const ADAPTER_AUDIENCE: &str = "adapter-native-proof";
const MACHINE_CLIENT: &str = "synthetic-adapter-machine";
const CHAT_CLIENT: &str = "synthetic-chat-host";
const GATEWAY_SCOPE: &str = "adapter:read";
const UPSTREAM_USERNAME: &str = "synthetic-reader";
const UPSTREAM_PASSWORD: &str = "synthetic-password";
const CURSOR_KEY: &str = "synthetic-cursor-key-0123456789!";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Project {
    GovStackFacilities,
    BregFacilities,
    BregWriteExample,
}

impl Project {
    fn project_directory(self, root: &Path) -> PathBuf {
        match self {
            Self::GovStackFacilities => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/adapter/govstack-facilities"),
            Self::BregFacilities => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/adapter/breg-facilities"),
            Self::BregWriteExample => root.join("examples/dhis2-tracker"),
        }
    }

    fn profile(self, root: &Path) -> PathBuf {
        root.join(match self {
            Self::GovStackFacilities => "profiles/govstack-consultation/profile.yaml",
            Self::BregFacilities | Self::BregWriteExample => "profiles/breg-records/profile.yaml",
        })
    }

    fn operations(self) -> [(&'static str, &'static str, &'static str); 2] {
        match self {
            Self::GovStackFacilities => [
                (
                    GET_TOOL,
                    "records-get.facilities",
                    "Read one configured facility.",
                ),
                (
                    SEARCH_TOOL,
                    "records-search.facilities",
                    "Search configured facilities by service area.",
                ),
            ],
            Self::BregFacilities => [
                (
                    GET_TOOL,
                    "records-get.facility",
                    "Read one configured facility through the Registry Record facade.",
                ),
                (
                    SEARCH_TOOL,
                    "records-search.facility",
                    "List configured facilities through the Registry Record facade.",
                ),
            ],
            Self::BregWriteExample => [
                (
                    GET_TOOL,
                    "records-get.person",
                    "Read one configured record.",
                ),
                (
                    SEARCH_TOOL,
                    "records-search.person",
                    "List configured records.",
                ),
            ],
        }
    }

    fn fixture_name(self) -> &'static str {
        match self {
            Self::GovStackFacilities => "govstack-facilities",
            Self::BregFacilities => "breg-facilities",
            Self::BregWriteExample => "breg-write-example",
        }
    }

    fn prepare(self, root: &Path, scratch: &Path) -> PreparedProject {
        let profile = self.profile(root);
        let pack = root.join("packs/dhis2-tracker/pack.yaml");
        let profile_digest = registry_platform_config::sha256_uri(
            &std::fs::read(&profile).expect("read immutable Adapter profile fixture"),
        );
        let pack_digest = registry_platform_config::sha256_uri(
            &std::fs::read(&pack).expect("read immutable Adapter pack fixture"),
        );
        let source = self.project_directory(root).join("project.yaml");
        let project = std::fs::read(source).expect("read native Adapter project fixture");
        let project = project_with_current_pins(&project, &profile_digest, &pack_digest);
        let directory = scratch
            .join("prepared-adapter-projects")
            .join(self.fixture_name());
        std::fs::create_dir_all(&directory).expect("create prepared Adapter project directory");
        std::fs::write(directory.join("project.yaml"), project)
            .expect("write prepared Adapter project copy");
        PreparedProject {
            directory,
            profile,
            pack,
        }
    }
}

#[derive(Clone, Debug)]
struct PreparedProject {
    directory: PathBuf,
    profile: PathBuf,
    pack: PathBuf,
}

fn project_with_current_pins(project: &[u8], profile_digest: &str, pack_digest: &str) -> String {
    let mut prepared = Reader::new("native Adapter project fixture")
        .scan(project)
        .expect("native Adapter project fixture is valid YAML")
        .expect("native Adapter project fixture is not empty")
        .to_json_value();
    *prepared
        .pointer_mut("/profile/digest")
        .expect("project fixture carries a profile digest pin") =
        Value::String(profile_digest.to_owned());
    *prepared
        .pointer_mut("/pack/digest")
        .expect("project fixture carries a pack digest pin") =
        Value::String(pack_digest.to_owned());
    let mut rendered =
        serde_json::to_string_pretty(&prepared).expect("serialize prepared Adapter project");
    rendered.push('\n');
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_project(project: &[u8]) -> Value {
        Reader::new("project transformation test")
            .scan(project)
            .expect("test project is valid YAML")
            .expect("test project is not empty")
            .to_json_value()
    }

    #[test]
    fn prepared_project_changes_only_the_profile_and_pack_digest_members() {
        let source = br#"apiVersion: test.example/project/v1
kind: TestProject
profile:
  id: profile
  digest: sha256:old-profile
  nested:
    digest: sha256:keep-profile-nested
pack:
  id: pack
  digest: sha256:old-pack
metadata:
  digest: sha256:keep-metadata
"#;
        let mut expected = parse_project(source);
        expected["profile"]["digest"] = json!("sha256:current-profile");
        expected["pack"]["digest"] = json!("sha256:current-pack");

        let prepared =
            project_with_current_pins(source, "sha256:current-profile", "sha256:current-pack");

        assert_eq!(parse_project(prepared.as_bytes()), expected);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayMode {
    Direct,
    InjectUnknownOutput,
}

pub struct NativeStack {
    pub source: Source,
    pub exported: Value,
    pub runtime_contract: Value,
    pub adapter_origin: String,
    pub resource: String,
    pub gateway_token: String,
    pub adapter_root: PathBuf,
    machine_token: String,
    database: String,
    authorization: TestAuthorizationServer,
    adapter: AdapterProcess,
    directory: tempfile::TempDir,
}

impl NativeStack {
    pub async fn start(
        runtime_project: Project,
        pinned_project: Project,
        gateway_mode: GatewayMode,
    ) -> Self {
        let adapter_bin = required_absolute_path("ADAPTER_BIN");
        let adapter_root = required_absolute_path("ADAPTER_FIXTURES_ROOT");
        assert!(
            adapter_root
                .join("profiles/govstack-consultation/profile.yaml")
                .is_file(),
            "ADAPTER_FIXTURES_ROOT must name the matching Adapter products/adapter tree"
        );
        assert!(
            adapter_root.join("packs/dhis2-tracker/pack.yaml").is_file(),
            "ADAPTER_FIXTURES_ROOT must carry the matching maintained pack"
        );
        let directory = tempfile::Builder::new()
            .prefix("registry-mcp-native-adapter-")
            .tempdir()
            .expect("native adapter scratch directory");
        let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("gateway listens");
        let resource = format!(
            "http://{}/mcp",
            gateway_listener.local_addr().expect("gateway address")
        );
        let authorization = TestAuthorizationServer::builder()
            .with_signing_key(
                generate_private_jwk(GeneratedKeyAlgorithm::Es256)
                    .expect("generate the synthetic ES256 issuer key"),
            )
            .client(TestClient::new(CHAT_CLIENT).with_resource(&resource))
            .client(
                TestClient::new(MACHINE_CLIENT)
                    .with_resource(ADAPTER_AUDIENCE)
                    .with_actor_kind(TestActorKind::Service),
            )
            .start()
            .await;
        let source = Source::start().await;
        let database = isolated_database_url().await;
        let adapter_port = free_port();
        let runtime_path = directory.path().join("adapter-runtime.yaml");
        write_adapter_runtime(&runtime_path, adapter_port, &source.origin, &authorization);
        let pinned_prepared = pinned_project.prepare(&adapter_root, directory.path());
        let runtime_prepared = if runtime_project == pinned_project {
            pinned_prepared.clone()
        } else {
            runtime_project.prepare(&adapter_root, directory.path())
        };
        let exported = export_contract(&adapter_bin, &pinned_prepared, &runtime_path, &database);
        let runtime_export = if runtime_project == pinned_project {
            exported.clone()
        } else {
            export_contract(&adapter_bin, &runtime_prepared, &runtime_path, &database)
        };
        let machine_token = authorization.issue_access_token(
            MACHINE_CLIENT,
            "synthetic-machine-principal",
            ADAPTER_AUDIENCE,
            "records.read",
            now() + 300,
        );
        let adapter = AdapterProcess::start(
            &adapter_bin,
            &runtime_prepared,
            &runtime_path,
            &database,
            adapter_port,
            directory.path().join("adapter.log"),
        )
        .await;
        let adapter_origin = format!("http://127.0.0.1:{adapter_port}");
        let runtime_contract = reqwest::Client::new()
            .get(format!(
                "{adapter_origin}/.well-known/registry-adapter/effective-contract"
            ))
            .bearer_auth(&machine_token)
            .send()
            .await
            .expect("read native adapter runtime contract")
            .error_for_status()
            .expect("native adapter runtime contract is ready")
            .json::<Value>()
            .await
            .expect("native adapter runtime contract JSON");
        assert_eq!(runtime_contract["digest"], runtime_export["digest"]);
        assert_eq!(runtime_contract["readiness"]["ready"], true);
        let provider_origin = match gateway_mode {
            GatewayMode::Direct => adapter_origin.clone(),
            GatewayMode::InjectUnknownOutput => {
                source::start_unknown_output_proxy(&adapter_origin).await
            }
        };
        let contract_path = directory.path().join("effective-contract.json");
        std::fs::write(
            &contract_path,
            serde_json::to_vec_pretty(&exported).expect("serialize effective contract"),
        )
        .expect("write effective contract pin");
        let expected_digest = exported["digest"].as_str().expect("contract digest");
        assert_eq!(
            registry_mcp::adapter::contract_digest(&exported["contract"])
                .expect("canonical effective contract digest"),
            expected_digest
        );
        registry_mcp::adapter::AdapterContract::load(&contract_path, expected_digest)
            .expect("the native exported contract is accepted by the gateway parser");
        let machine_token_path = directory.path().join("secrets").join("adapter-token");
        let audit_key_path = directory.path().join("secrets").join("audit-key");
        std::fs::create_dir(directory.path().join("secrets")).expect("gateway secret directory");
        write_secret(&machine_token_path, &machine_token);
        write_secret(
            &audit_key_path,
            "synthetic-audit-hash-key-0123456789abcdef0123456789abcdef",
        );
        let gateway_path = directory.path().join("gateway-runtime.yaml");
        let operations = pinned_project.operations();
        write_gateway_runtime(
            &gateway_path,
            &resource,
            &authorization,
            &provider_origin,
            &contract_path,
            expected_digest,
            directory.path(),
            &operations,
        );
        let config = RuntimeConfig::load(&gateway_path).expect("gateway runtime config loads");
        let router = runtime::build(&config)
            .await
            .expect("gateway router builds");
        tokio::spawn(async move {
            axum::serve(gateway_listener, router)
                .await
                .expect("gateway serves");
        });
        let gateway_token = authorization.issue_access_token(
            CHAT_CLIENT,
            "synthetic-gateway-caller",
            &resource,
            GATEWAY_SCOPE,
            now() + 300,
        );
        Self {
            source,
            exported,
            runtime_contract,
            adapter_origin,
            resource,
            gateway_token,
            adapter_root,
            machine_token,
            database,
            authorization,
            adapter,
            directory,
        }
    }

    pub async fn client(&self) -> RunningService<RoleClient, ()> {
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(self.resource.clone())
                .auth_header(self.gateway_token.clone()),
        );
        ().serve(transport).await.expect("MCP client connects")
    }

    pub fn export(&self, project: Project) -> Value {
        let prepared = project.prepare(&self.adapter_root, self.directory.path());
        export_contract(
            &required_absolute_path("ADAPTER_BIN"),
            &prepared,
            &self.directory.path().join("adapter-runtime.yaml"),
            &self.database,
        )
    }

    pub async fn write_binding_error(&self) -> String {
        let breg = self.export(Project::BregWriteExample);
        let write_operation = breg["contract"]["unserved"]
            .as_array()
            .expect("BReg example exports unserved operations")
            .iter()
            .find(|operation| operation["support"] == "unserved" && operation["effect"] == "write")
            .and_then(|operation| operation["operationId"].as_str())
            .expect("BReg example exports an unserved write operation")
            .to_owned();
        let path = self.directory.path().join("breg-effective-contract.json");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&breg).expect("serialize BReg adapter contract"),
        )
        .expect("write BReg adapter contract");
        let runtime_path = self.directory.path().join("write-operation-gateway.yaml");
        write_gateway_runtime(
            &runtime_path,
            &self.resource,
            &self.authorization,
            &self.adapter_origin,
            &path,
            breg["digest"].as_str().expect("BReg contract digest"),
            self.directory.path(),
            &[(
                "create_registry_person",
                write_operation.as_str(),
                "Create is outside this read-only gateway.",
            )],
        );
        match RuntimeConfig::load(&runtime_path) {
            Ok(config) => runtime::build(&config)
                .await
                .expect_err("a producer-declared write cannot build a read-only provider")
                .to_string(),
            Err(error) => error,
        }
    }

    pub async fn break_journal(&self) {
        let (client, connection) = tokio_postgres::connect(&self.database, tokio_postgres::NoTls)
            .await
            .expect("connect native adapter journal");
        tokio::spawn(connection);
        client
            .batch_execute(
                "ALTER TABLE adapter_journal_events RENAME TO adapter_journal_events_unavailable",
            )
            .await
            .expect("make the owned adapter journal unavailable");
    }

    pub fn gateway_audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.directory.path().join("gateway-audit.jsonl"))
            .expect("read gateway audit")
            .lines()
            .map(|line| serde_json::from_str(line).expect("gateway audit JSON line"))
            .collect()
    }

    pub fn adapter_log(&self) -> String {
        std::fs::read_to_string(&self.adapter.log_path).expect("read Adapter operational log")
    }

    pub async fn adapter_journal_text(&self) -> String {
        let (client, connection) = tokio_postgres::connect(&self.database, tokio_postgres::NoTls)
            .await
            .expect("connect native adapter journal");
        tokio::spawn(connection);
        client
            .query(
                "SELECT row_to_json(events)::text FROM adapter_journal_events AS events",
                &[],
            )
            .await
            .expect("read native adapter journal")
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub async fn direct_get_with_correlation(
        &self,
        record_id: &str,
        correlation: &str,
    ) -> reqwest::Response {
        self.direct_get(
            record_id,
            self.exported["digest"].as_str().expect("contract digest"),
            Some(correlation),
        )
        .await
    }

    pub async fn direct_get_with_contract_pin(
        &self,
        record_id: &str,
        pin: &str,
    ) -> reqwest::Response {
        self.direct_get(record_id, pin, None).await
    }

    async fn direct_get(
        &self,
        record_id: &str,
        pin: &str,
        correlation: Option<&str>,
    ) -> reqwest::Response {
        let mut request = reqwest::Client::new()
            .get(format!(
                "{}/v1/collections/facilities/records/{record_id}",
                self.adapter_origin
            ))
            .bearer_auth(&self.machine_token)
            .header("x-registry-adapter-contract", pin);
        if let Some(correlation) = correlation {
            request = request.header("x-registry-correlation-id", correlation);
        }
        request
            .send()
            .await
            .expect("direct native Adapter contract probe")
    }

    pub fn adapter_is_running(&mut self) -> bool {
        self.adapter
            .child
            .try_wait()
            .expect("poll native adapter")
            .is_none()
    }
}

pub async fn call(
    client: &RunningService<RoleClient, ()>,
    tool: &str,
    arguments: Value,
) -> CallToolResult {
    let arguments = arguments
        .as_object()
        .cloned()
        .expect("tool arguments are an object");
    client
        .call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments))
        .await
        .expect("MCP tool call completes")
}

pub fn structured(result: &CallToolResult) -> Value {
    result
        .structured_content
        .clone()
        .expect("MCP result carries structured content")
}

pub fn error_code(result: &CallToolResult) -> &str {
    assert_eq!(result.is_error, Some(true), "{result:?}");
    result
        .structured_content
        .as_ref()
        .and_then(|value| value.pointer("/error/code"))
        .and_then(Value::as_str)
        .expect("structured MCP error code")
}

struct AdapterProcess {
    child: Child,
    log_path: PathBuf,
}

impl AdapterProcess {
    async fn start(
        binary: &Path,
        project: &PreparedProject,
        runtime: &Path,
        database: &str,
        port: u16,
        log_path: PathBuf,
    ) -> Self {
        let log = std::fs::File::create(&log_path).expect("create Adapter operational log");
        let mut command = adapter_command(binary, project, runtime, "serve");
        command
            .env("TEST_DB_URL", database)
            .env("TEST_UPSTREAM_USERNAME", UPSTREAM_USERNAME)
            .env("TEST_UPSTREAM_PASSWORD", UPSTREAM_PASSWORD)
            .env("TEST_CURSOR_KEY", CURSOR_KEY)
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        let child = command.spawn().expect("native adapter binary starts");
        let mut process = Self { child, log_path };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = process.child.try_wait().expect("poll native adapter") {
                panic!(
                    "native adapter exited early ({status}): {}",
                    process.stderr()
                );
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return process;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "native adapter did not listen"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn stderr(&mut self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    fn stop(&mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stderr()
    }
}

impl Drop for AdapterProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn export_contract(
    binary: &Path,
    project: &PreparedProject,
    runtime: &Path,
    database: &str,
) -> Value {
    let mut command = adapter_command(binary, project, runtime, "effective-contract");
    let output = command
        .env("TEST_DB_URL", database)
        .env("TEST_UPSTREAM_USERNAME", UPSTREAM_USERNAME)
        .env("TEST_UPSTREAM_PASSWORD", UPSTREAM_PASSWORD)
        .env("TEST_CURSOR_KEY", CURSOR_KEY)
        .output()
        .expect("run native adapter effective-contract export");
    assert!(
        output.status.success(),
        "native adapter effective-contract export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("native adapter effective contract JSON")
}

fn adapter_command(
    binary: &Path,
    project: &PreparedProject,
    runtime: &Path,
    subcommand: &str,
) -> Command {
    let mut command = Command::new(binary);
    command
        .arg(subcommand)
        .arg("--runtime-config")
        .arg(runtime)
        .arg("--project")
        .arg(&project.directory)
        .arg("--profile")
        .arg(&project.profile)
        .arg("--pack")
        .arg(&project.pack);
    command
}

fn write_adapter_runtime(
    path: &Path,
    port: u16,
    source: &str,
    authorization: &TestAuthorizationServer,
) {
    std::fs::write(
        path,
        format!(
            r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: native-mcp-proof
endpoints:
  - endpoint: tracker
    baseUrl: {source}
    credential:
      type: basic
      usernameRef: secret:env/TEST_UPSTREAM_USERNAME
      passwordRef: secret:env/TEST_UPSTREAM_PASSWORD
listener:
  bind: 127.0.0.1:{port}
database:
  runtimeUrlRef: secret:env/TEST_DB_URL
  migrationUrlRef: secret:env/TEST_DB_URL
  testOnlyPlaintext: true
oidc:
  issuer: {issuer}
  audience: {ADAPTER_AUDIENCE}
  allowInsecureHttp: true
  jwksSource:
    type: uri
    uri: {jwks}
allowedClients: [{MACHINE_CLIENT}]
allowedPrivateCidrs: [192.168.0.0/16]
audit:
  retentionDays: 90
idempotency:
  responseRetentionSeconds: 86400
cursorKeyRef: secret:env/TEST_CURSOR_KEY
"#,
            issuer = authorization.issuer(),
            jwks = authorization.jwks_uri(),
        ),
    )
    .expect("write adapter runtime config");
}

#[allow(clippy::too_many_arguments)]
fn write_gateway_runtime(
    path: &Path,
    resource: &str,
    authorization: &TestAuthorizationServer,
    adapter_origin: &str,
    contract_file: &Path,
    digest: &str,
    scratch: &Path,
    operations: &[(&str, &str, &str)],
) {
    let tools = operations
        .iter()
        .map(|(tool, _, _)| format!("      - {tool}"))
        .collect::<Vec<_>>()
        .join("\n");
    let operation_map = operations
        .iter()
        .map(|(tool, operation, description)| {
            format!(
                "        {tool}:\n          operation: {operation}\n          description: {description}"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(
        path,
        format!(
            r#"apiVersion: id.registrystack.org/formats/platform/mcp-runtime/v1alpha1
kind: PlatformMcpRuntimeConfig
name: Native adapter proof
logLevel: info
listener:
  bind: 127.0.0.1:1
  tlsTermination: development-loopback
secretProviders:
  file:
    root: {secrets}
resourceServer:
  resource: {resource}
  issuer: {issuer}
  allowInsecureHttp: true
  jwksSource:
    type: uri
    uri: {jwks}
  algorithms: [ES256]
  allowedClients: [{CHAT_CLIENT}]
  requiredScopes: [{GATEWAY_SCOPE}]
  maximumTokenLifetimeSeconds: 3600
audit:
  hashKeyRef: secret:file/audit-key
  destination: file
  path: {audit}
rateLimits:
  perPrincipal:
    requestsPerMinute: 1000
    burst: 1000
  perClient:
    requestsPerMinute: 1000
    burst: 1000
bindings:
  - name: native-adapter
    tools:
{tools}
    provider:
      type: adapter
      baseUrl: {adapter_origin}
      contractFile: {contract_file}
      contractDigest: {digest}
      dataClass: non-personal
      audience: {ADAPTER_AUDIENCE}
      machineTokenRef: secret:file/adapter-token
      operations:
{operation_map}
"#,
            secrets = scratch.join("secrets").display(),
            issuer = authorization.issuer(),
            jwks = authorization.jwks_uri(),
            audit = scratch.join("gateway-audit.jsonl").display(),
            contract_file = contract_file.display(),
        ),
    )
    .expect("write gateway runtime config");
}

async fn isolated_database_url() -> String {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names an owned disposable PostgreSQL server");
    let schema = format!("mcp_native_adapter_{}", uuid::Uuid::new_v4().simple());
    let (client, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect disposable PostgreSQL server");
    tokio::spawn(connection);
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create isolated native adapter journal schema");
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    tokio_postgres::Config::from_str(&url).expect("isolated PostgreSQL URL parses");
    url
}

fn required_absolute_path(name: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(name)
            .unwrap_or_else(|| panic!("{name} is required for the native Adapter proof")),
    );
    assert!(path.is_absolute(), "{name} must be an absolute path");
    path
}

fn write_secret(path: &Path, value: &str) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create owner-only test secret");
    file.write_all(value.as_bytes()).expect("write test secret");
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind adapter test port")
        .local_addr()
        .expect("adapter test port")
        .port()
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("time fits")
}

pub fn get_arguments(record_id: &str) -> Value {
    json!({"path":{"record_id":record_id},"query":{}})
}

pub fn search_arguments(org_unit: &str, cursor: Option<&str>) -> Value {
    let mut body = json!({
        "search":"byCriteria",
        "criteria":{"org_unit":org_unit},
        "pageSize":5
    });
    if let Some(cursor) = cursor {
        body["cursor"] = Value::String(cursor.to_owned());
    }
    json!({"path":{},"query":{},"body":body})
}
