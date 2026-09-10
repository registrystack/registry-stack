// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use registry_casework::{
    secret_resolver, validate_breg_source_description, verify_policy_package,
    PolicyPackageManifest, PostgresStore, RuntimeConfig, POLICY_PACKAGE_MANIFEST_FILE,
};
use registry_casework_core::{CaseworkProject, SourceAdapter as _};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const CASEWORK_YAML: &str = r#"apiVersion: registry.registrystack.org/casework/v1alpha1
kind: CaseworkProject
casework:
  id: professional-review
  version: "1"
accessProfiles:
  - id: staff
    principalClaim: registry_principal
    requiredScopes: [casework:staff]
    role: staff
  - id: supervisor
    principalClaim: registry_principal
    requiredScopes: [casework:supervisor]
    role: supervisor
  - id: administrator
    principalClaim: registry_principal
    requiredScopes: [casework:admin]
    role: administrator
sources:
  - id: professional-register
    adapter: breg
    description: sources/professional-register.json
    requests:
      - entity: scope-correction
        queue: corrections
        target:
          id: first-review-response
          after: {elapsed: PT48H}
queues:
  - id: corrections
    label: Licence corrections
"#;

const OPERATOR_YAML: &str = r#"project: casework.yaml
listen: 127.0.0.1:8091
tlsTermination: development-loopback
networkExposure: private-address
secretProviders:
  file:
    root: secrets
database:
  runtimeUrlRef: secret:env/CASEWORK_DATABASE_URL
  migrationUrlRef: secret:env/CASEWORK_MIGRATION_DATABASE_URL
authentication:
  oidc:
    issuer: https://identity.example.test/realms/registry
    audience: urn:example:casework
    scopeClaim: registry_scopes
    # The trusted issuer must add this claim only to interactive human sessions.
    # Client-credentials and other service tokens must omit it or use another value.
    humanIdentity:
      claim: registry_actor_kind
      value: human
audit:
  path: state/audit.ndjson
  secretRef: secret:file/casework-audit-key
sources:
  professional-register:
    baseUrl: https://registry.example.test
    readerProfile: casework-reader
    tokenEndpoint: https://identity.example.test/realms/registry/token
    clientIdRef: secret:file/breg-reader-client-id
    clientAssertionKeyRef: secret:file/breg-reader-key
    webhookSecretRef: secret:file/breg-casework-webhook
    eventSource: urn:registrystack:registry:professional-licences:instance:professional-licences-starter
"#;

#[cfg(test)]
const BREG_SOURCE_DESCRIPTION: &str = r#"{
  "apiVersion": "registry.registrystack.org/casework-source-description/v1alpha1",
  "kind": "BRegCaseworkSourceDescription",
  "origin": "bregctl explain change-requests",
  "authority": "none",
  "sourceId": "professional-register",
  "sourceRevision": "sha256:source-revision",
  "request": {
    "requestEntity": "scope-correction",
    "requestRoute": "scope-corrections",
    "reviewMode": "staged",
    "stages": [{"id":"review","approvals":1,"excludeSubmitter":true,"excludePreviousReviewers":false}],
    "fields": [],
    "contractFingerprint": "sha256:contract",
    "application": {"mode":"manual"}
  }
}
"#;

const FIXTURE: &str = r#"apiVersion: registry.registrystack.org/casework-fixture/v1alpha1
kind: CaseworkFixture
name: professional-review-offline
source:
  id: professional-register
  requestEntity: scope-correction
  reviewStage: review
expect:
  queue: corrections
  applicationMode: manual
  targetElapsed: PT48H
"#;

const STANDALONE_YAML: &str = r#"apiVersion: registry.registrystack.org/casework/v1alpha1
kind: CaseworkProject
casework:
  id: standalone-decision
  version: "1"
accessProfiles:
  - id: staff
    principalClaim: sub
    requiredScopes: [casework:staff]
    role: staff
  - id: supervisor
    principalClaim: sub
    requiredScopes: [casework:supervisor]
    role: supervisor
  - id: administrator
    principalClaim: sub
    requiredScopes: [casework:admin]
    role: administrator
  - id: requester
    principalClaim: sub
    requiredScopes: [casework:request]
    role: requester
    kinds: [decision]
queues:
  - id: decisions
    label: Decisions awaiting review
hostedKinds:
  - id: decision
    version: "1"
    queue: decisions
    decidingProfiles: [staff]
    retention:
      terminalDays: 90
      accountabilityDays: 365
    displaySchema:
      type: object
      additionalProperties: false
      required: [summary, reference]
      properties:
        summary: {type: string, maxLength: 160}
        reference: {type: string, maxLength: 120}
    outcomes:
      - id: confirmed
        label: Confirm
        reasonRequired: false
      - id: rejected
        label: Return for correction
        reasonRequired: true
"#;

const STANDALONE_FIXTURE: &str = r#"apiVersion: registry.registrystack.org/casework-fixture/v1alpha1
kind: CaseworkFixture
name: standalone-decision-offline
hosted:
  kind: decision
  display:
    summary: Confirm the prepared synthetic batch
    reference: synthetic-batch-0042
expect:
  queue: decisions
  outcomes: [confirmed, rejected]
"#;

pub(super) fn init(project: &Path, template: &str) -> Result<Value> {
    let (project_yaml, fixture_name, fixture, next) = match template {
        "professional-review" => (CASEWORK_YAML, "professional-review.yaml", FIXTURE,
            "Run caseworkctl source add with the authored BReg project and --source-id professional-register."),
        "standalone-decision" => (STANDALONE_YAML, "standalone-decision.yaml", STANDALONE_FIXTURE,
            "Run caseworkctl check and test, configure operator.yaml with database and identity settings, then create a team serving decisions as an Administrator."),
        _ => bail!("unknown template {template:?}; available templates: professional-review, standalone-decision"),
    };
    if project.exists() {
        bail!("destination already exists; init never overwrites a project");
    }
    let parent = project
        .parent()
        .context("project destination has no parent")?;
    fs::create_dir_all(parent).context("creating project parent")?;
    let staging = tempfile::Builder::new()
        .prefix(".casework-init-")
        .tempdir_in(parent)
        .context("creating project staging directory")?;
    fs::create_dir(staging.path().join("fixtures"))?;
    fs::create_dir(staging.path().join("sources"))?;
    fs::write(staging.path().join("casework.yaml"), project_yaml)?;
    let operator_yaml = if template == "standalone-decision" {
        OPERATOR_YAML
            .split("\nsources:")
            .next()
            .unwrap_or(OPERATOR_YAML)
    } else {
        OPERATOR_YAML
    };
    fs::write(staging.path().join("operator.example.yaml"), operator_yaml)?;
    fs::write(staging.path().join("fixtures").join(fixture_name), fixture)?;
    let staging_path = staging.keep();
    fs::rename(&staging_path, project)
        .context("publishing Casework project without replacement")?;
    Ok(json!({
        "ok": true,
        "command": "init",
        "template": template,
        "project": project,
        "created": ["casework.yaml", "operator.example.yaml", format!("fixtures/{fixture_name}"), "sources/"],
        "next": [next]
    }))
}

pub(super) fn check(project: &Path) -> Result<Value> {
    let policy = load_and_check_policy(project)?;
    if policy.sources.is_empty() {
        return Ok(json!({
            "ok": true,
            "command": "check",
            "project": project,
            "effective": {
                "projectId": policy.casework.id,
                "mode": "standalone",
                "queues": policy.queues,
                "hostedKinds": policy.hosted_kinds,
                "inbox": policy.inbox,
                "sourceConnections": 0
            },
            "networkAccess": false,
            "databaseAccess": false
        }));
    }
    let source_description = if policy
        .sources
        .iter()
        .all(|source| project.join(&source.description).is_file())
    {
        check_source_descriptions(project)?;
        crate::policy::check(project, &policy)?;
        "checked"
    } else {
        "pending_source_add"
    };
    let source = &policy.sources[0];
    let request = &source.requests[0];
    let inbox = serde_json::to_value(&policy.inbox)?;
    Ok(json!({
        "ok": true,
        "command": "check",
        "project": project,
        "effective": {
            "projectId": policy.casework.id,
            "sourceId": source.id,
            "sourceAdapter": source.adapter,
            "requestEntity": request.entity,
            "queue": request.queue,
            "queueMode": if request.routing.is_empty() { "default" } else { "first_match" },
            "routingRules": request.routing.len(),
            "applicationMode": "manual",
            "sourceDescription": source_description,
            "queueTarget": {"clock":"first_observed_elapsed", "elapsed": request.target.as_ref().map(|target| target.after.elapsed.as_str()), "worker":false},
            "inbox": inbox,
            "limits": {"sources":policy.sources.len(), "queues":policy.queues.len()}
        },
        "networkAccess": false,
        "databaseAccess": false
    }))
}

pub(super) fn test(project: &Path) -> Result<Value> {
    let checked = check(project)?;
    let policy = load_and_check_policy(project)?;
    let effective = &checked["effective"];
    let fixture_dir = project.join("fixtures");
    let mut paths = fs::read_dir(&fixture_dir)
        .context("reading fixtures directory")?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("yaml"))
        .collect::<Vec<_>>();
    paths.sort();
    if paths.is_empty() {
        bail!("test requires at least one YAML fixture");
    }
    let mut reports = Vec::new();
    for path in paths {
        let fixture = load_yaml(&path, "fixture")?;
        let name = if fixture.get("subject").is_some() || fixture.get("now").is_some() {
            crate::policy::simulate(project, &policy, &path)
                .with_context(|| format!("simulation fixture {}", path.display()))?["fixture"]
                .clone()
        } else {
            validate_fixture(&fixture, effective, &policy)
                .with_context(|| format!("fixture {}", path.display()))?;
            fixture["name"].clone()
        };
        reports.push(json!({
            "name": name,
            "status": "passed",
            "file": path.strip_prefix(project).unwrap_or(&path)
        }));
    }
    Ok(json!({
        "ok": true,
        "command": "test",
        "project": project,
        "fixtures": reports,
        "networkAccess": false,
        "databaseAccess": false
    }))
}

fn load_yaml(path: &Path, label: &str) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("reading {label}"))?;
    if bytes.len() > 1024 * 1024 {
        bail!("{label} exceeds the one MiB authoring limit");
    }
    serde_norway::from_slice(&bytes).with_context(|| format!("parsing {label}"))
}
fn load_and_check_policy(project: &Path) -> Result<CaseworkProject> {
    let policy = CaseworkProject::load(project.join("casework.yaml"))
        .context("loading and checking casework.yaml")?;
    if policy.sources.is_empty() {
        if policy.hosted_kinds.is_empty() {
            bail!("declare a hosted kind or connect a source before checking the project");
        }
        return Ok(policy);
    }
    if policy
        .sources
        .iter()
        .any(|source| source.adapter != "breg" || source.requests.len() != 1)
    {
        bail!("each source must use the breg adapter and declare one request entity");
    }
    Ok(policy)
}

pub(super) fn explain(project: &Path) -> Result<Value> {
    let policy = load_and_check_policy(project)?;
    check_source_descriptions(project)?;
    crate::policy::explain(project, &policy)
}

pub(super) fn simulate(project: &Path, fixture: &Path) -> Result<Value> {
    let policy = load_and_check_policy(project)?;
    check_source_descriptions(project)?;
    crate::policy::simulate(project, &policy, fixture)
}

pub(super) fn package(project: &Path, output: &Path) -> Result<Value> {
    let project = fs::canonicalize(project).context("resolving the Casework authoring project")?;
    let policy = load_and_check_policy(&project)?;
    check_source_descriptions(&project)?;
    crate::policy::check(&project, &policy)?;

    let mut inputs = vec![(
        "casework.yaml".to_owned(),
        read_package_input(&project.join("casework.yaml"))?,
    )];
    for source in &policy.sources {
        let path = project_input_path(&project, &source.description)?;
        inputs.push((source.description.clone(), read_package_input(&path)?));
    }
    let manifest = PolicyPackageManifest::build(inputs.clone())
        .context("building the Casework policy package identity")?;

    if output.exists() {
        bail!("policy package output already exists");
    }
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).context("creating the policy package parent directory")?;
    }
    fs::create_dir(output).context("creating the new policy package directory")?;
    let published = (|| -> Result<()> {
        for (relative, bytes) in &inputs {
            let target = output.join(relative);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).context("creating policy package directories")?;
            }
            fs::write(&target, bytes).context("writing a policy package input")?;
        }
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        manifest_bytes.push(b'\n');
        fs::write(output.join(POLICY_PACKAGE_MANIFEST_FILE), manifest_bytes)
            .context("writing the policy package manifest")?;
        let loaded = CaseworkProject::load(output.join("casework.yaml"))
            .context("loading the staged Casework policy")?;
        let verified = verify_policy_package(&output.join("casework.yaml"), &loaded)
            .context("verifying the staged Casework policy package")?;
        if verified.as_deref() != Some(manifest.policy_digest.as_str()) {
            bail!("staged Casework policy package identity changed");
        }
        Ok(())
    })();
    if let Err(error) = published {
        let _ = fs::remove_dir_all(output);
        return Err(error);
    }

    Ok(json!({
        "ok": true,
        "command": "package",
        "project": project,
        "output": output,
        "policyDigest": manifest.policy_digest,
        "files": manifest.files,
        "operatorConfigurationIncluded": false,
        "secretsIncluded": false,
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

fn read_package_input(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading package input metadata {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 1024 * 1024
    {
        bail!("package input must be a regular file of at most one MiB");
    }
    fs::read(path).with_context(|| format!("reading package input {}", path.display()))
}

fn project_input_path(project: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("source description path must be a normalized path inside the project");
    }
    let project = fs::canonicalize(project).context("resolving the Casework project")?;
    let candidate = fs::canonicalize(project.join(path))
        .context("resolving the imported source description")?;
    if !candidate.starts_with(&project) {
        bail!("source description path leaves the Casework project");
    }
    Ok(candidate)
}

fn validate_fixture(fixture: &Value, effective: &Value, policy: &CaseworkProject) -> Result<()> {
    if fixture["apiVersion"] != "registry.registrystack.org/casework-fixture/v1alpha1"
        || fixture["kind"] != "CaseworkFixture"
    {
        bail!("fixture must declare the v1alpha1 CaseworkFixture contract");
    }
    if let Some(hosted) = fixture.get("hosted") {
        let kind_id = hosted["kind"]
            .as_str()
            .context("hosted fixture requires a kind")?;
        let kind = policy
            .hosted_kinds
            .iter()
            .find(|kind| kind.id == kind_id)
            .context("hosted fixture names an undeclared kind")?;
        kind.validate_display(&hosted["display"])
            .context("hosted fixture display does not satisfy the kind schema")?;
        let outcomes = kind
            .outcomes
            .iter()
            .map(|outcome| outcome.id.as_str())
            .collect::<Vec<_>>();
        if fixture["expect"]["queue"] != kind.queue
            || fixture["expect"]["outcomes"] != json!(outcomes)
        {
            bail!("hosted fixture queue or outcomes do not match the declared kind");
        }
        return Ok(());
    }
    let assertions = [
        (
            &fixture["source"]["id"],
            &effective["sourceId"],
            "source id",
        ),
        (
            &fixture["source"]["requestEntity"],
            &effective["requestEntity"],
            "request entity",
        ),
        (&fixture["expect"]["queue"], &effective["queue"], "queue"),
        (
            &fixture["expect"]["applicationMode"],
            &effective["applicationMode"],
            "application mode",
        ),
        (
            &fixture["expect"]["targetElapsed"],
            &effective["queueTarget"]["elapsed"],
            "target elapsed time",
        ),
    ];
    for (actual, expected, label) in assertions {
        if actual != expected {
            bail!("{label} expectation does not match the effective project");
        }
    }
    Ok(())
}

pub(super) fn doctor(project: &Path, operator: Option<&Path>) -> Result<Value> {
    let (project, operator, config) = load_runtime(project, operator)?;
    check_source_descriptions(&project)?;
    let resolver = secret_resolver(&config).context("configuring Casework secret providers")?;
    // Resolve the audit key as a readiness check without retaining or reporting
    // its bytes. Database references are resolved inside PostgresStore.
    resolver
        .resolve(&config.audit.secret_ref)
        .context("the audit secret is unavailable")?;
    let runtime = async_runtime()?;
    let policy = load_and_check_policy(&project)?;
    if config.sources.len() != policy.sources.len() {
        bail!("operator source bindings do not exactly match the authored Casework sources");
    }
    for source in &policy.sources {
        let binding = config
            .sources
            .get(&source.id)
            .with_context(|| format!("operator source binding {} is missing", source.id))?;
        let adapter = binding
            .build_adapter(source, &project, &resolver)
            .with_context(|| format!("source binding {} is invalid", source.id))?;
        runtime
            .block_on(adapter.discover_active(None, 1))
            .with_context(|| {
                format!(
                    "source {} is unavailable or its read-only profile cannot list active requests",
                    source.id
                )
            })?;
    }
    let store = PostgresStore::connect_runtime(&config.database, &resolver)
        .context("the Casework runtime database configuration is invalid")?;
    runtime
        .block_on(store.ready())
        .context("the Casework runtime database is unavailable")?;
    runtime
        .block_on(config.oidc_verifier(&resolver))
        .context("the configured OIDC issuer is unavailable or incompatible")?;
    if !runtime
        .block_on(store.directory_ready())
        .context("checking Casework directory readiness")?
    {
        bail!("the Casework directory has no team serving the default queue; authenticate as an Administrator and create the team and queue assignment before retrying doctor");
    }
    Ok(json!({
        "ok": true,
        "command": "doctor",
        "project": project,
        "operator": operator,
        "checks": {
            "configuration": "ready",
            "sourceDescriptions": "ready",
            "sourceConnections": "ready",
            "database": "ready",
            "oidcIssuer": "ready",
            "directory": "ready"
        }
    }))
}

pub(super) fn db_migrate(project: &Path, operator: Option<&Path>) -> Result<Value> {
    let (project, operator, config) = load_runtime(project, operator)?;
    let resolver = secret_resolver(&config).context("configuring Casework secret providers")?;
    let store = PostgresStore::connect_migration(&config.database, &resolver)
        .context("the Casework migration database configuration is invalid")?;
    async_runtime()?
        .block_on(store.migrate())
        .context("applying Casework database migrations")?;
    Ok(json!({
        "ok": true,
        "command": "db migrate",
        "project": project,
        "operator": operator,
        "status": "migrated"
    }))
}

pub(super) fn dev_start(project: &Path, operator: Option<&Path>) -> Result<Value> {
    let (project, operator, config) = load_runtime(project, operator)?;
    let state = state_paths(&project);
    fs::create_dir_all(&state.directory).context("creating local Casework state")?;
    if let Some(process) = read_process(&state.pid)? {
        if process_matches(&process)? {
            bail!("a local Casework runtime is already running for this project");
        }
        fs::remove_file(&state.pid).context("removing a stale Casework pid file")?;
    }
    rotate_journal(&state.journal)?;
    let journal = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&state.journal)
        .context("opening the local Casework journal")?;
    let stderr = journal.try_clone()?;
    let binary = std::env::var_os("CASEWORK_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("casework"));
    check_casework_version(&binary)?;
    let mut child = Command::new(&binary)
        .args([
            "--config",
            operator.to_str().context("operator path is not UTF-8")?,
            "serve",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(journal))
        .stderr(Stdio::from(stderr))
        .spawn()
        .context(
            "starting casework; set CASEWORK_BIN to the same-version binary if it is not on PATH",
        )?;
    let process = ProcessRecord {
        pid: child.id(),
        binary: binary.clone(),
        operator: operator.clone(),
    };
    write_process(&state.pid, &process)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().context("checking the Casework child")? {
            let _ = fs::remove_file(&state.pid);
            bail!("Casework exited before readiness with {status}; inspect caseworkctl dev events");
        }
        if probe_ready(config.listen) {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&state.pid);
            bail!(
                "Casework did not report ready within 10 seconds; inspect caseworkctl dev events"
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(json!({
        "ok": true,
        "command": "dev start",
        "project": project,
        "operator": operator,
        "pid": process.pid,
        "listen": config.listen,
        "health": "ready",
        "journal": state.journal
    }))
}

pub(super) fn dev_stop(project: &Path) -> Result<Value> {
    let project = fs::canonicalize(project).context("resolving Casework project")?;
    let state = state_paths(&project);
    let Some(process) = read_process(&state.pid)? else {
        bail!("no local Casework runtime exists in this project; nothing was stopped");
    };
    if !process_matches(&process)? {
        fs::remove_file(&state.pid).context("removing stale Casework pid state")?;
        bail!("the retained Casework process is no longer running; stale state was removed");
    }
    signal(process.pid, "-TERM")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while process_matches(&process)? {
        if Instant::now() >= deadline {
            signal(process.pid, "-KILL")?;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    fs::remove_file(&state.pid).context("removing Casework pid state")?;
    Ok(
        json!({"ok":true,"command":"dev stop","project":project,"pid":process.pid,"status":"stopped"}),
    )
}

pub(super) fn dev_events(project: &Path) -> Result<Value> {
    let project = fs::canonicalize(project).context("resolving Casework project")?;
    let journal = state_paths(&project).journal;
    const MAX_BYTES: u64 = 256 * 1024;
    let (bytes, byte_truncated) = match fs::File::open(&journal) {
        Ok(mut file) => {
            let length = file
                .metadata()
                .context("reading local Casework journal metadata")?
                .len();
            let start = length.saturating_sub(MAX_BYTES);
            file.seek(SeekFrom::Start(start))
                .context("seeking local Casework journal tail")?;
            let mut bytes = Vec::with_capacity(
                usize::try_from(length.min(MAX_BYTES)).context("sizing Casework journal tail")?,
            );
            file.take(MAX_BYTES)
                .read_to_end(&mut bytes)
                .context("reading local Casework journal tail")?;
            (bytes, start > 0)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (Vec::new(), false),
        Err(error) => return Err(error).context("opening local Casework journal"),
    };
    let text = String::from_utf8_lossy(&bytes);
    let lines = text.lines().collect::<Vec<_>>();
    let line_truncated = lines.len() > 512;
    let first_line = if line_truncated { lines.len() - 512 } else { 0 };
    let events = lines.into_iter().skip(first_line).collect::<Vec<_>>();
    Ok(
        json!({"ok":true,"command":"dev events","project":project,"journal":journal,"events":events,"truncated":byte_truncated || line_truncated}),
    )
}

fn operator_path(project: &Path, requested: Option<&Path>) -> PathBuf {
    requested
        .map(Path::to_path_buf)
        .unwrap_or_else(|| project.join("operator.yaml"))
}

fn load_runtime(
    project: &Path,
    requested: Option<&Path>,
) -> Result<(PathBuf, PathBuf, RuntimeConfig)> {
    let project = fs::canonicalize(project).context("resolving Casework project")?;
    load_and_check_policy(&project)?;
    let operator = fs::canonicalize(operator_path(&project, requested))
        .context("resolving Casework operator configuration")?;
    let config =
        RuntimeConfig::load(&operator).context("loading Casework operator configuration")?;
    if fs::canonicalize(&config.project).context("resolving operator project binding")?
        != project
            .join("casework.yaml")
            .canonicalize()
            .context("resolving casework.yaml")?
    {
        bail!("operator configuration is bound to a different Casework project");
    }
    Ok((project, operator, config))
}

fn check_source_descriptions(project: &Path) -> Result<()> {
    let policy = load_and_check_policy(project)?;
    for source in policy.sources {
        let path = project_input_path(project, &source.description)?;
        let bytes = read_package_input(&path)?;
        validate_breg_source_description(&source, &bytes).map_err(|_| {
            anyhow::anyhow!("source description {} does not match the exact BReg adapter contract bound to this source; repeat source add", path.display())
        })?;
    }
    Ok(())
}

fn async_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the Casework operator runtime")
}

struct StatePaths {
    directory: PathBuf,
    pid: PathBuf,
    journal: PathBuf,
}

fn state_paths(project: &Path) -> StatePaths {
    let directory = project.join(".casework");
    StatePaths {
        pid: directory.join("dev-process.json"),
        journal: directory.join("events.log"),
        directory,
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ProcessRecord {
    pid: u32,
    binary: PathBuf,
    operator: PathBuf,
}

fn read_process(path: &Path) -> Result<Option<ProcessRecord>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .context("reading retained Casework process state"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("reading retained Casework process state"),
    }
}

fn write_process(path: &Path, process: &ProcessRecord) -> Result<()> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().context("pid path has no parent")?)?;
    serde_json::to_writer(&mut temporary, process)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn process_matches(process: &ProcessRecord) -> Result<bool> {
    let output = Command::new("ps")
        .args(["-p", &process.pid.to_string(), "-o", "command="])
        .output()
        .context("checking retained Casework process")?;
    if !output.status.success() {
        return Ok(false);
    }
    let command = String::from_utf8_lossy(&output.stdout);
    Ok(command.contains("casework")
        && command.contains(process.operator.to_string_lossy().as_ref()))
}

fn signal(pid: u32, signal: &str) -> Result<()> {
    let status = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .context("signalling retained Casework process")?;
    if !status.success() {
        bail!("could not signal retained Casework process {pid}");
    }
    Ok(())
}

fn check_casework_version(binary: &Path) -> Result<()> {
    let output = Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .context("starting casework for its version")?;
    let expected = format!("casework {}", registry_platform_buildinfo::DISPLAY_VERSION);
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != expected {
        bail!("dev start requires {expected}");
    }
    Ok(())
}

fn probe_ready(address: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(250)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    if stream
        .write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = [0_u8; 64];
    let Ok(length) = stream.read(&mut response) else {
        return false;
    };
    response[..length].starts_with(b"HTTP/1.1 200")
        || response[..length].starts_with(b"HTTP/1.1 204")
}

fn rotate_journal(path: &Path) -> Result<()> {
    if fs::metadata(path).is_ok_and(|metadata| metadata.len() > 1024 * 1024) {
        let bytes = fs::read(path)?;
        fs::write(path, &bytes[bytes.len().saturating_sub(256 * 1024)..])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_has_only_checkpoint_capabilities() {
        let policy: CaseworkProject = serde_norway::from_str(CASEWORK_YAML).unwrap();
        policy.check().unwrap();
        assert_eq!(policy.sources.len(), 1);
        assert_eq!(policy.queues.len(), 1);
    }

    #[test]
    fn fixture_exercises_effective_defaults() {
        let fixture: Value = serde_norway::from_str(FIXTURE).unwrap();
        let effective = json!({"sourceId":"professional-register","requestEntity":"scope-correction","queue":"corrections","applicationMode":"manual","queueTarget":{"elapsed":"PT48H"}});
        validate_fixture(
            &fixture,
            &effective,
            &serde_norway::from_str(CASEWORK_YAML).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn standalone_starter_checks_real_display_schema_without_a_source() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        init(&project, "standalone-decision").unwrap();
        let checked = check(&project).unwrap();
        assert_eq!(
            load_and_check_policy(&project).unwrap().hosted_kinds,
            vec![registry_casework_core::standalone_decision_starter_kind()]
        );
        assert_eq!(checked["effective"]["mode"], "standalone");
        assert_eq!(checked["effective"]["sourceConnections"], 0);
        test(&project).unwrap();
        let fixture = project.join("fixtures/standalone-decision.yaml");
        let mut value = load_yaml(&fixture, "fixture").unwrap();
        value["hosted"]["display"]["undeclared"] = json!("synthetic");
        fs::write(&fixture, serde_norway::to_string(&value).unwrap()).unwrap();
        assert!(test(&project).is_err());
        let operator = RuntimeConfig::load(project.join("operator.example.yaml")).unwrap();
        assert!(operator.sources.is_empty());
    }

    #[test]
    fn package_stages_only_verified_policy_inputs_and_refuses_replacement() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        let output = root.path().join("deployment/policy");
        init(&project, "standalone-decision").unwrap();

        let report = package(&project, &output).unwrap();
        assert_eq!(report["command"], "package");
        assert!(report["policyDigest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(report["operatorConfigurationIncluded"], false);
        assert_eq!(report["secretsIncluded"], false);
        assert!(output.join("casework.yaml").is_file());
        assert!(output.join(POLICY_PACKAGE_MANIFEST_FILE).is_file());
        assert!(!output.join("operator.example.yaml").exists());
        assert!(!output.join("fixtures").exists());
        assert!(package(&project, &output).is_err());

        fs::write(output.join("undeclared-input.json"), "{}\n").unwrap();
        let policy = CaseworkProject::load(output.join("casework.yaml")).unwrap();
        assert!(verify_policy_package(&output.join("casework.yaml"), &policy).is_err());
    }

    #[test]
    fn package_pins_the_exact_strictly_decoded_source_description() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("authored");
        let output = root.path().join("package");
        fs::create_dir_all(project.join("sources")).unwrap();
        fs::write(project.join("casework.yaml"), CASEWORK_YAML).unwrap();
        fs::write(
            project.join("sources/professional-register.json"),
            BREG_SOURCE_DESCRIPTION,
        )
        .unwrap();

        package(&project, &output).unwrap();
        assert!(output.join("sources/professional-register.json").is_file());
        let policy = CaseworkProject::load(output.join("casework.yaml")).unwrap();
        assert!(
            verify_policy_package(&output.join("casework.yaml"), &policy)
                .unwrap()
                .is_some()
        );
        fs::write(output.join("sources/professional-register.json"), "{}\n").unwrap();
        assert!(verify_policy_package(&output.join("casework.yaml"), &policy).is_err());
    }

    #[test]
    fn source_description_paths_cannot_leave_the_project() {
        let root = tempfile::tempdir().unwrap();
        assert!(project_input_path(root.path(), "../source.json").is_err());
        assert!(project_input_path(root.path(), "/tmp/source.json").is_err());
    }

    #[test]
    fn generated_operator_config_loads_through_runtime_contract() {
        assert_eq!(
            OPERATOR_YAML,
            include_str!(
                "../../../products/casework/examples/professional-review/operator.example.yaml"
            )
        );
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("casework.yaml"), CASEWORK_YAML).unwrap();
        fs::create_dir(directory.path().join("sources")).unwrap();
        fs::write(
            directory.path().join("sources/professional-register.json"),
            BREG_SOURCE_DESCRIPTION,
        )
        .unwrap();
        let operator = directory.path().join("operator.yaml");
        fs::write(&operator, OPERATOR_YAML).unwrap();
        let config = RuntimeConfig::load(operator).unwrap();
        assert_eq!(config.listen, "127.0.0.1:8091".parse().unwrap());
        assert!(config.sources.contains_key("professional-register"));
    }

    #[test]
    fn dev_events_returns_only_the_bounded_journal_tail() {
        let project = tempfile::tempdir().unwrap();
        let state = state_paths(project.path());
        fs::create_dir_all(&state.directory).unwrap();
        let mut journal = String::new();
        for index in 0..700 {
            journal.push_str(&format!("event-{index:04}-{}\n", "x".repeat(500)));
        }
        fs::write(&state.journal, journal).unwrap();

        let result = dev_events(project.path()).unwrap();
        let events = result["events"].as_array().unwrap();
        let expected_last = format!("event-0699-{}", "x".repeat(500));
        assert!(result["truncated"].as_bool().unwrap());
        assert!(events.len() <= 512);
        assert_eq!(
            events.last().and_then(Value::as_str),
            Some(expected_last.as_str())
        );
        assert!(
            events
                .iter()
                .filter_map(Value::as_str)
                .map(str::len)
                .sum::<usize>()
                <= 256 * 1024
        );

        let short_lines = (0..600)
            .map(|index| format!("short-{index:04}"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&state.journal, short_lines).unwrap();
        let line_limited = dev_events(project.path()).unwrap();
        let events = line_limited["events"].as_array().unwrap();
        assert_eq!(events.len(), 512);
        assert!(line_limited["truncated"].as_bool().unwrap());
        assert_eq!(events.first().and_then(Value::as_str), Some("short-0088"));
        assert_eq!(events.last().and_then(Value::as_str), Some("short-0599"));
    }
}
