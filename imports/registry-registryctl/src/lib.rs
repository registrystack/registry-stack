use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use registry_platform_authcommon::{
    credential_fingerprint_commitment, fingerprint_api_key, validate_api_key_entropy,
    CredentialCommitmentContext, CredentialProduct, CredentialType,
};
use serde::{Deserialize, Serialize};

pub use crate::sample::Sample;

mod sample;
mod stored_zip;

const RELAY_IMAGE: &str = "ghcr.io/jeremi/registry-relay:snapshot";
const RELAY_BASE_URL: &str = "http://127.0.0.1:4242";
const RELAY_DOCS_PATH: &str = "/docs";

pub fn init_spreadsheet_api(dir: &Path, sample: Sample) -> Result<()> {
    match sample {
        Sample::Benefits => init_benefits_project(dir),
    }
}

pub fn start_project(project_dir: &Path) -> Result<()> {
    start_project_with_timeout(project_dir, Duration::from_secs(60))
}

fn start_project_with_timeout(project_dir: &Path, timeout: Duration) -> Result<()> {
    let project = Project::load(project_dir)?;
    validate_project_fingerprints(project_dir, &project)?;
    run_compose(project_dir, &["up", "-d"])?;
    wait_for_ready(&project.runtime.relay_base_url, timeout)?;
    println!("Relay API:  {}", project.runtime.relay_base_url);
    println!(
        "API docs:   {}{}",
        project.runtime.relay_base_url, RELAY_DOCS_PATH
    );
    Ok(())
}

pub fn stop_project(project_dir: &Path) -> Result<()> {
    Project::load(project_dir)?;
    run_compose(project_dir, &["down"])?;
    Ok(())
}

pub fn status_project(project_dir: &Path) -> Result<()> {
    let project = Project::load(project_dir)?;
    run_compose(project_dir, &["ps"])?;
    print_probe_status(
        "healthz",
        &format!("{}/healthz", project.runtime.relay_base_url),
    );
    print_probe_status(
        "ready",
        &format!("{}/ready", project.runtime.relay_base_url),
    );
    println!("Relay API:  {}", project.runtime.relay_base_url);
    println!(
        "API docs:   {}{}",
        project.runtime.relay_base_url, RELAY_DOCS_PATH
    );
    Ok(())
}

pub fn open_project(project_dir: &Path) -> Result<()> {
    let project = Project::load(project_dir)?;
    let docs_url = format!("{}{}", project.runtime.relay_base_url, RELAY_DOCS_PATH);
    let open_result = Command::new("open").arg(&docs_url).status();
    if !matches!(open_result, Ok(status) if status.success()) {
        println!("{docs_url}");
    }
    Ok(())
}

pub fn logs_project(project_dir: &Path) -> Result<()> {
    Project::load(project_dir)?;
    run_compose(project_dir, &["logs"])?;
    Ok(())
}

pub fn smoke_project(project_dir: &Path) -> Result<()> {
    let project = Project::load(project_dir)?;
    validate_project_fingerprints(project_dir, &project)?;
    let secrets = LocalEnv::load(&project_dir.join(&project.local.secrets_env))?;
    let report = run_smoke_checks(&project.runtime.relay_base_url, &secrets);
    let output_path = project_dir
        .join(project.local.output_dir)
        .join("smoke-results.json");
    fs::create_dir_all(output_path.parent().unwrap_or(project_dir))?;
    let json =
        serde_json::to_string_pretty(&report).context("failed to render smoke result JSON")?;
    parse_smoke_report(&json)?;
    write_text(output_path, &json)?;

    for check in &report.checks {
        let status = if check.passed { "PASS" } else { "FAIL" };
        println!("{status} {}", check.name);
    }

    if report.passed {
        Ok(())
    } else {
        bail!("one or more smoke checks failed")
    }
}

fn init_benefits_project(dir: &Path) -> Result<()> {
    if dir.exists() {
        let mut entries =
            fs::read_dir(dir).with_context(|| format!("failed to inspect {}", dir.display()))?;
        if entries.next().is_some() {
            bail!(
                "target directory already exists and is not empty: {}",
                dir.display()
            );
        }
    }

    fs::create_dir_all(dir.join("relay"))?;
    fs::create_dir_all(dir.join("data"))?;
    fs::create_dir_all(dir.join("secrets"))?;
    fs::create_dir_all(dir.join("output"))?;

    let credentials = LocalCredentials::generate()?;
    write_text(dir.join("registryctl.yaml"), &registryctl_manifest(dir)?)?;
    write_text(dir.join("compose.yaml"), compose_yaml())?;
    write_text(dir.join("README.md"), project_readme())?;
    write_text(dir.join(".gitignore"), include_str!("templates/gitignore"))?;
    write_text(dir.join("relay/config.yaml"), &relay_config(&credentials))?;
    write_text(dir.join("relay/metadata.yaml"), relay_metadata())?;
    write_text(dir.join("secrets/local.env"), &credentials.env_file())?;
    write_text(dir.join("output/.gitkeep"), "")?;
    sample::write_benefits_workbook(&dir.join("data/benefits_casework.xlsx"))?;
    Ok(())
}

fn write_text(path: PathBuf, contents: &str) -> Result<()> {
    fs::write(&path, contents).with_context(|| format!("failed to write {}", path.display()))
}

#[derive(Debug, Deserialize)]
struct Project {
    relay: ProjectRelay,
    runtime: ProjectRuntime,
    local: ProjectLocal,
}

impl Project {
    fn load(project_dir: &Path) -> Result<Self> {
        let path = project_dir.join("registryctl.yaml");
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))
    }
}

#[derive(Debug, Deserialize)]
struct ProjectRelay {
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ProjectRuntime {
    relay_base_url: String,
}

#[derive(Debug, Deserialize)]
struct ProjectLocal {
    secrets_env: PathBuf,
    output_dir: PathBuf,
}

#[derive(Debug)]
struct LocalEnv {
    values: BTreeMap<String, String>,
}

impl LocalEnv {
    fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Ok(Self {
            values: parse_local_env(&contents),
        })
    }

    fn required(&self, name: &str) -> Result<&str> {
        self.values
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("missing required local env value {name}"))
    }

    fn value(&self, name: &str) -> &str {
        self.values.get(name).map(String::as_str).unwrap_or("")
    }
}

fn parse_local_env(contents: &str) -> BTreeMap<String, String> {
    contents
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn run_compose(project_dir: &Path, args: &[&str]) -> Result<()> {
    run_compose_command(project_dir, "docker", args)
}

fn run_compose_command(project_dir: &Path, binary: &str, args: &[&str]) -> Result<()> {
    let command_args = compose_command_args("compose.yaml", args);
    let status = Command::new(binary)
        .args(&command_args)
        .current_dir(project_dir)
        .status()
        .with_context(|| format!("failed to run {binary} compose"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("{binary} compose exited with {status}")
    }
}

fn compose_command_args(compose_file: &str, args: &[&str]) -> Vec<String> {
    ["compose", "-f", compose_file]
        .into_iter()
        .chain(args.iter().copied())
        .map(String::from)
        .collect()
}

fn validate_project_fingerprints(project_dir: &Path, project: &Project) -> Result<()> {
    let config_path = project_dir.join(&project.relay.config);
    let config = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config: serde_yaml::Value = serde_yaml::from_str(&config)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;
    let secrets = LocalEnv::load(&project_dir.join(&project.local.secrets_env))?;
    let api_keys = config["auth"]["api_keys"]
        .as_sequence()
        .ok_or_else(|| anyhow!("relay config auth.api_keys must be a list"))?;

    for api_key in api_keys {
        let id = api_key["id"]
            .as_str()
            .ok_or_else(|| anyhow!("relay config api key entry is missing id"))?;
        let hash_env = api_key["fingerprint"]["name"]
            .as_str()
            .ok_or_else(|| anyhow!("relay config api key {id} is missing fingerprint env name"))?;
        let configured_commitment = api_key["fingerprint"]["commitment"]
            .as_str()
            .ok_or_else(|| anyhow!("relay config api key {id} is missing commitment"))?;

        let fingerprint = secrets.required(hash_env)?;
        let raw_env = raw_env_name_for(id)?;
        let raw_key = secrets.required(raw_env)?;
        let expected_fingerprint = fingerprint_api_key(raw_key);
        if fingerprint != expected_fingerprint {
            bail!("local raw key and fingerprint do not match for {id}");
        }

        let expected_commitment = credential_fingerprint_commitment(
            CredentialCommitmentContext {
                product: CredentialProduct::RegistryRelay,
                credential_type: CredentialType::ApiKey,
                credential_id: id,
            },
            fingerprint,
        );
        if configured_commitment != expected_commitment {
            bail!("local fingerprint commitment does not match relay config for {id}");
        }
    }

    Ok(())
}

fn raw_env_name_for(id: &str) -> Result<&'static str> {
    match id {
        "metadata_reader" => Ok("METADATA_READER_RAW"),
        "row_reader" => Ok("ROW_READER_RAW"),
        "aggregate_reader" => Ok("AGGREGATE_READER_RAW"),
        _ => bail!("unknown generated api key id {id}"),
    }
}

fn wait_for_ready(base_url: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let health = http_get(&format!("{base_url}/healthz"), &[]).ok();
        let ready = http_get(&format!("{base_url}/ready"), &[]).ok();
        if matches!(health.as_ref().map(|response| response.status), Some(200))
            && matches!(ready.as_ref().map(|response| response.status), Some(200))
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    bail!("Relay did not become healthy and ready before timeout")
}

fn print_probe_status(name: &str, url: &str) {
    match http_get(url, &[]) {
        Ok(response) => println!("{name}: {}", response.status),
        Err(err) => println!("{name}: unavailable ({err})"),
    }
}

#[derive(Debug)]
struct LocalCredentials {
    metadata_reader: Credential,
    row_reader: Credential,
    aggregate_reader: Credential,
    audit_hash_secret: String,
}

impl LocalCredentials {
    fn generate() -> Result<Self> {
        Ok(Self {
            metadata_reader: Credential::generate("metadata_reader")?,
            row_reader: Credential::generate("row_reader")?,
            aggregate_reader: Credential::generate("aggregate_reader")?,
            audit_hash_secret: random_token(48)?,
        })
    }

    fn env_file(&self) -> String {
        format!(
            "\
METADATA_READER_RAW={metadata_raw}
METADATA_READER_HASH={metadata_hash}
ROW_READER_RAW={row_raw}
ROW_READER_HASH={row_hash}
AGGREGATE_READER_RAW={aggregate_raw}
AGGREGATE_READER_HASH={aggregate_hash}
REGISTRY_RELAY_AUDIT_HASH_SECRET={audit_hash_secret}
",
            metadata_raw = self.metadata_reader.raw,
            metadata_hash = self.metadata_reader.fingerprint,
            row_raw = self.row_reader.raw,
            row_hash = self.row_reader.fingerprint,
            aggregate_raw = self.aggregate_reader.raw,
            aggregate_hash = self.aggregate_reader.fingerprint,
            audit_hash_secret = self.audit_hash_secret,
        )
    }
}

#[derive(Debug)]
struct Credential {
    id: &'static str,
    raw: String,
    fingerprint: String,
    commitment: String,
}

impl Credential {
    fn generate(id: &'static str) -> Result<Self> {
        let raw = random_token(32)?;
        validate_api_key_entropy(&raw)?;
        let fingerprint = fingerprint_api_key(&raw);
        let commitment = credential_fingerprint_commitment(
            CredentialCommitmentContext {
                product: CredentialProduct::RegistryRelay,
                credential_type: CredentialType::ApiKey,
                credential_id: id,
            },
            &fingerprint,
        );
        Ok(Self {
            id,
            raw,
            fingerprint,
            commitment,
        })
    }
}

fn random_token(byte_len: usize) -> Result<String> {
    let mut bytes = vec![0_u8; byte_len];
    getrandom::fill(&mut bytes).map_err(|err| anyhow!("random generation failed: {err}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

#[derive(Serialize)]
struct ProjectManifest<'a> {
    schema_version: &'a str,
    project: ProjectSection<'a>,
    runtime: RuntimeSection<'a>,
    relay: RelaySection<'a>,
    local: LocalSection<'a>,
}

#[derive(Serialize)]
struct ProjectSection<'a> {
    name: String,
    kind: &'a str,
    product: &'a str,
}

#[derive(Serialize)]
struct RuntimeSection<'a> {
    engine: &'a str,
    compose_file: &'a str,
    relay_image: &'a str,
    relay_base_url: &'a str,
}

#[derive(Serialize)]
struct RelaySection<'a> {
    config: &'a str,
    metadata: &'a str,
    data: Vec<&'a str>,
}

#[derive(Serialize)]
struct LocalSection<'a> {
    secrets_env: &'a str,
    output_dir: &'a str,
}

fn registryctl_manifest(dir: &Path) -> Result<String> {
    let name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("my-first-api")
        .to_string();
    let manifest = ProjectManifest {
        schema_version: "registryctl/v1",
        project: ProjectSection {
            name,
            kind: "spreadsheet-api",
            product: "registry-relay",
        },
        runtime: RuntimeSection {
            engine: "docker_compose",
            compose_file: "compose.yaml",
            relay_image: RELAY_IMAGE,
            relay_base_url: RELAY_BASE_URL,
        },
        relay: RelaySection {
            config: "relay/config.yaml",
            metadata: "relay/metadata.yaml",
            data: vec!["data/benefits_casework.xlsx"],
        },
        local: LocalSection {
            secrets_env: "secrets/local.env",
            output_dir: "output",
        },
    };
    serde_yaml::to_string(&manifest).context("failed to render registryctl manifest")
}

fn compose_yaml() -> &'static str {
    include_str!("templates/compose.yaml")
}

fn project_readme() -> &'static str {
    include_str!("templates/project_readme.md")
}

fn relay_config(credentials: &LocalCredentials) -> String {
    include_str!("templates/relay_config.yaml.tmpl")
        .replace("{{metadata_id}}", credentials.metadata_reader.id)
        .replace(
            "{{metadata_commitment}}",
            &credentials.metadata_reader.commitment,
        )
        .replace("{{row_id}}", credentials.row_reader.id)
        .replace("{{row_commitment}}", &credentials.row_reader.commitment)
        .replace("{{aggregate_id}}", credentials.aggregate_reader.id)
        .replace(
            "{{aggregate_commitment}}",
            &credentials.aggregate_reader.commitment,
        )
}

fn relay_metadata() -> &'static str {
    include_str!("templates/relay_metadata.yaml")
}

#[derive(Debug, Deserialize, Serialize)]
struct SmokeReport {
    base_url: String,
    passed: bool,
    checks: Vec<SmokeCheck>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SmokeCheck {
    name: String,
    method: String,
    path: String,
    expected_status: u16,
    actual_status: Option<u16>,
    passed: bool,
    error: Option<String>,
}

fn run_smoke_checks(base_url: &str, secrets: &LocalEnv) -> SmokeReport {
    let mut checks = Vec::new();

    record_smoke_check(
        &mut checks,
        base_url,
        "healthz is public",
        "/healthz",
        200,
        &[],
    );
    record_smoke_check(&mut checks, base_url, "ready is public", "/ready", 200, &[]);
    record_smoke_check(
        &mut checks,
        base_url,
        "anonymous dataset request is denied",
        "/v1/datasets",
        401,
        &[],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "metadata key can list datasets",
        "/v1/datasets",
        200,
        &[bearer_header(secrets.value("METADATA_READER_RAW"))],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "metadata key cannot read rows",
        "/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
        403,
        &[
            bearer_header(secrets.value("METADATA_READER_RAW")),
            (
                "Data-Purpose".to_string(),
                "https://example.local/purpose/tutorial".to_string(),
            ),
        ],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "row read without Data-Purpose returns 400",
        "/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
        400,
        &[bearer_header(secrets.value("ROW_READER_RAW"))],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "row reader can read filtered records",
        "/v1/datasets/benefits_casework/entities/person/records?household_id=hh-1001",
        200,
        &[
            bearer_header(secrets.value("ROW_READER_RAW")),
            (
                "Data-Purpose".to_string(),
                "https://example.local/purpose/tutorial".to_string(),
            ),
        ],
    );
    record_smoke_check(
        &mut checks,
        base_url,
        "authorized key can fetch runtime OpenAPI",
        "/openapi.json",
        200,
        &[bearer_header(secrets.value("METADATA_READER_RAW"))],
    );

    SmokeReport {
        base_url: base_url.to_string(),
        passed: checks.iter().all(|check| check.passed),
        checks,
    }
}

fn parse_smoke_report(contents: &str) -> Result<SmokeReport> {
    serde_json::from_str(contents).context("failed to parse smoke result JSON")
}

fn record_smoke_check(
    checks: &mut Vec<SmokeCheck>,
    base_url: &str,
    name: &'static str,
    path: &'static str,
    expected_status: u16,
    headers: &[(String, String)],
) {
    let url = format!("{base_url}{path}");
    match http_get(&url, headers) {
        Ok(response) => checks.push(SmokeCheck {
            name: name.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            expected_status,
            actual_status: Some(response.status),
            passed: response.status == expected_status,
            error: None,
        }),
        Err(err) => checks.push(SmokeCheck {
            name: name.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            expected_status,
            actual_status: None,
            passed: false,
            error: Some(redact_error(&err.to_string())),
        }),
    }
}

fn bearer_header(raw_key: &str) -> (String, String) {
    ("Authorization".to_string(), format!("Bearer {raw_key}"))
}

fn redact_error(error: &str) -> String {
    if error.len() > 240 {
        format!("{}...", &error[..240])
    } else {
        error.to_string()
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
}

fn http_get(url: &str, headers: &[(String, String)]) -> Result<HttpResponse> {
    let parsed = ParsedHttpUrl::parse(url)?;
    let addr = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("could not resolve {}", parsed.host))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .with_context(|| format!("failed to connect to {}", parsed.authority()))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    write!(
        stream,
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        parsed.path, parsed.host
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "\r\n")?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid HTTP response from {}", parsed.authority()))?;
    Ok(HttpResponse { status })
}

#[derive(Debug)]
struct ParsedHttpUrl {
    host: String,
    port: u16,
    path: String,
}

impl ParsedHttpUrl {
    fn parse(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| anyhow!("only http:// local URLs are supported"))?;
        let (authority, path) = rest
            .split_once('/')
            .map(|(authority, path)| (authority, format!("/{path}")))
            .unwrap_or_else(|| (rest, "/".to_string()));
        let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
            let parsed_port = port
                .parse::<u16>()
                .with_context(|| format!("invalid URL port in {url}"))?;
            (host.to_string(), parsed_port)
        } else {
            (authority.to_string(), 80)
        };
        Ok(Self { host, port, path })
    }

    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use registry_platform_authcommon::{
        credential_fingerprint_commitment, CredentialCommitmentContext, CredentialProduct,
        CredentialType,
    };
    use serde_yaml::Value;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn init_sample_creates_expected_project_tree() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");

        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        for path in [
            "registryctl.yaml",
            "compose.yaml",
            "README.md",
            ".gitignore",
            "relay/config.yaml",
            "relay/metadata.yaml",
            "data/benefits_casework.xlsx",
            "secrets/local.env",
            "output/.gitkeep",
        ] {
            assert!(project.join(path).exists(), "{path} should exist");
        }
    }

    #[test]
    fn manifest_pins_image_and_records_base_url() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let manifest: Value =
            serde_yaml::from_str(&fs::read_to_string(project.join("registryctl.yaml")).unwrap())
                .unwrap();
        assert_eq!(manifest["runtime"]["relay_image"], RELAY_IMAGE);
        assert_ne!(manifest["runtime"]["relay_image"], "latest");
        assert_eq!(manifest["runtime"]["relay_base_url"], RELAY_BASE_URL);
    }

    #[test]
    fn generated_gitignore_excludes_local_secrets_and_output() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let gitignore = fs::read_to_string(project.join(".gitignore")).unwrap();
        assert!(gitignore.lines().any(|line| line == "secrets/"));
        assert!(gitignore.lines().any(|line| line == "output/"));
    }

    #[test]
    fn generated_credentials_match_config_commitments() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        let config = fs::read_to_string(project.join("relay/config.yaml")).unwrap();

        for (id, env_name) in [
            ("metadata_reader", "METADATA_READER_HASH"),
            ("row_reader", "ROW_READER_HASH"),
            ("aggregate_reader", "AGGREGATE_READER_HASH"),
        ] {
            let fingerprint = env_value(&env, env_name);
            let commitment = credential_fingerprint_commitment(
                CredentialCommitmentContext {
                    product: CredentialProduct::RegistryRelay,
                    credential_type: CredentialType::ApiKey,
                    credential_id: id,
                },
                &fingerprint,
            );
            assert!(
                config.contains(&commitment),
                "config should contain commitment for {id}"
            );
        }
    }

    #[test]
    fn generated_fingerprint_preflight_passes_for_clean_project() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();

        let project = Project::load(&project_dir).unwrap();
        validate_project_fingerprints(&project_dir, &project).unwrap();
    }

    #[test]
    fn generated_fingerprint_preflight_fails_when_hash_changes() {
        for (env_name, id) in [
            ("METADATA_READER_HASH", "metadata_reader"),
            ("ROW_READER_HASH", "row_reader"),
            ("AGGREGATE_READER_HASH", "aggregate_reader"),
        ] {
            let temp = TempDir::new().unwrap();
            let project_dir = temp.path().join("my-first-api");
            init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();

            let env_path = project_dir.join("secrets/local.env");
            let mut env = fs::read_to_string(&env_path).unwrap();
            let original = env_value(&env, env_name);
            env = env.replace(
                &original,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            );
            fs::write(&env_path, env).unwrap();

            let project = Project::load(&project_dir).unwrap();
            let error = validate_project_fingerprints(&project_dir, &project).unwrap_err();
            assert!(error.to_string().contains(&format!(
                "local raw key and fingerprint do not match for {id}"
            )));
        }
    }

    #[test]
    fn generated_fingerprint_preflight_fails_when_hash_is_missing() {
        for env_name in [
            "METADATA_READER_HASH",
            "ROW_READER_HASH",
            "AGGREGATE_READER_HASH",
        ] {
            let temp = TempDir::new().unwrap();
            let project_dir = temp.path().join("my-first-api");
            init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();

            let env_path = project_dir.join("secrets/local.env");
            let env = fs::read_to_string(&env_path).unwrap();
            let filtered: String = env
                .lines()
                .filter(|line| !line.starts_with(&format!("{env_name}=")))
                .map(|line| format!("{line}\n"))
                .collect();
            fs::write(&env_path, filtered).unwrap();

            let project = Project::load(&project_dir).unwrap();
            let error = validate_project_fingerprints(&project_dir, &project).unwrap_err();
            assert!(error
                .to_string()
                .contains(&format!("missing required local env value {env_name}")));
        }
    }

    #[test]
    fn generated_public_files_do_not_contain_raw_keys_or_fingerprints() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let env = fs::read_to_string(project.join("secrets/local.env")).unwrap();
        let secrets: BTreeSet<_> = env
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter(|(name, _)| name.ends_with("_RAW") || name.ends_with("_HASH"))
            .map(|(_, value)| value.to_string())
            .collect();

        for path in [
            "registryctl.yaml",
            "compose.yaml",
            "README.md",
            "relay/config.yaml",
            "relay/metadata.yaml",
        ] {
            let contents = fs::read_to_string(project.join(path)).unwrap();
            for secret in &secrets {
                assert!(
                    !contents.contains(secret),
                    "{path} should not contain generated secret/fingerprint"
                );
            }
        }
    }

    #[test]
    fn generated_workbook_is_xlsx_with_benefits_sample_sheets() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("my-first-api");
        init_spreadsheet_api(&project, Sample::Benefits).unwrap();

        let workbook = fs::read(project.join("data/benefits_casework.xlsx")).unwrap();
        assert!(workbook.starts_with(b"PK"));
        let lossy = String::from_utf8_lossy(&workbook);
        assert!(lossy.contains("Households"));
        assert!(lossy.contains("Persons"));
        assert!(lossy.contains("hh-1001"));
    }

    #[test]
    fn compose_command_arguments_are_stable() {
        assert_eq!(
            compose_command_args("compose.yaml", &["up", "-d"]),
            ["compose", "-f", "compose.yaml", "up", "-d"]
        );
    }

    #[test]
    fn compose_runner_surfaces_nonzero_exit() {
        let temp = TempDir::new().unwrap();

        run_compose_command(temp.path(), "true", &["ps"]).unwrap();
        let error = run_compose_command(temp.path(), "false", &["ps"]).unwrap_err();

        assert!(error.to_string().contains("false compose exited"));
    }

    #[test]
    fn readiness_wait_fails_after_bounded_timeout() {
        let error = wait_for_ready("http://127.0.0.1:1", Duration::from_millis(1)).unwrap_err();

        assert!(error
            .to_string()
            .contains("Relay did not become healthy and ready before timeout"));
    }

    #[test]
    fn parses_local_http_urls_for_smoke_checks() {
        let parsed = ParsedHttpUrl::parse("http://127.0.0.1:4242/v1/datasets?x=y").unwrap();
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 4242);
        assert_eq!(parsed.path, "/v1/datasets?x=y");

        let default_port = ParsedHttpUrl::parse("http://localhost/healthz").unwrap();
        assert_eq!(default_port.host, "localhost");
        assert_eq!(default_port.port, 80);
        assert_eq!(default_port.path, "/healthz");
    }

    #[test]
    fn smoke_report_json_does_not_include_local_keys() {
        let secrets = LocalEnv {
            values: BTreeMap::from([
                (
                    "METADATA_READER_RAW".to_string(),
                    "metadata-secret".to_string(),
                ),
                ("ROW_READER_RAW".to_string(), "row-secret".to_string()),
            ]),
        };
        let report = run_smoke_checks("http://127.0.0.1:1", &secrets);
        let json = serde_json::to_string(&report).unwrap();
        let parsed = parse_smoke_report(&json).unwrap();

        assert!(!json.contains("metadata-secret"));
        assert!(!json.contains("row-secret"));
        assert!(!report.passed);
        assert_eq!(parsed.checks.len(), 8);
    }

    #[test]
    fn smoke_project_writes_redacted_failure_report() {
        let temp = TempDir::new().unwrap();
        let project_dir = temp.path().join("my-first-api");
        init_spreadsheet_api(&project_dir, Sample::Benefits).unwrap();

        let error = smoke_project(&project_dir).unwrap_err();
        assert!(error
            .to_string()
            .contains("one or more smoke checks failed"));

        let env = fs::read_to_string(project_dir.join("secrets/local.env")).unwrap();
        let report = fs::read_to_string(project_dir.join("output/smoke-results.json")).unwrap();
        for (_, secret) in env.lines().filter_map(|line| line.split_once('=')) {
            assert!(!report.contains(secret));
        }
        assert!(report.contains("\"passed\": false"));
    }

    fn env_value(env: &str, name: &str) -> String {
        env.lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then(|| value.to_string()))
            .unwrap_or_else(|| panic!("{name} should be present"))
    }
}
