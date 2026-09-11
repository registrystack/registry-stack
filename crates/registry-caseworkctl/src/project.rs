// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use registry_casework::{
    secret_resolver, validate_breg_source_description, verify_policy_package,
    PolicyPackageManifest, PostgresStore, RuntimeConfig, POLICY_PACKAGE_MANIFEST_FILE,
};
use registry_casework_core::{
    AttemptSettlement, AttemptSettlementReport, CaseworkProject, SourceRetentionReport,
    SourceRetentionSelector,
};
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

const RUNTIME_SCHEMA: &str =
    include_str!("../../../products/casework/generated/runtime/runtime.schema.json");

fn runtime_example(project: &Path, include_source: bool) -> Result<String> {
    let package_root = if project.is_absolute() {
        project.to_path_buf()
    } else {
        std::env::current_dir()?.join(project)
    };
    let mut document = json!({
        "apiVersion": "registry.registrystack.org/casework-runtime/v1alpha1",
        "kind": "CaseworkRuntimeConfig",
        "package": {"root": &package_root},
        "listener": {"bind": "127.0.0.1:8100", "tlsTermination": "development-loopback", "networkExposure": "private-address"},
        "secretProviders": {"file": {"root": package_root.join("secrets")}},
        "database": {"runtimeUrlRef": "secret:file/runtime-database-url", "migrationUrlRef": "secret:file/migration-database-url"},
        "authentication": {"oidc": {
            "issuer": "https://identity.example.test/realms/registry",
            "audience": "urn:example:casework",
            "scopeClaim": "registry_scopes",
            "humanIdentity": {"claim": "registry_actor_kind", "value": "human"}
        }},
        "audit": {"path": package_root.join("state/audit.ndjson"), "hashKeyRef": "secret:file/casework-audit-key"},
        "sources": {}
    });
    if include_source {
        document["sources"]["professional-register"] = json!({
            "baseUrl": "https://registry.example.test",
            "readerProfile": "casework-reader",
            "tokenEndpoint": "https://identity.example.test/realms/registry/token",
            "clientIdRef": "secret:file/breg-reader-client-id",
            "clientAssertionKeyRef": "secret:file/breg-reader-key",
            "webhookSecretRef": "secret:file/breg-casework-webhook",
            "eventSource": "urn:registrystack:registry:professional-licences:instance:professional-licences-starter"
        });
    }
    serde_norway::to_string(&document).context("rendering runtime.example.yaml")
}

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

const EVENT_WIRING_GUIDANCE: &str = "The configured source reader cannot attest that BReg sends lifecycle events to this Casework receiver with the same key. Run bregctl doctor against the BReg runtime configuration, then cause and confirm one lifecycle delivery.";

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
            "Run caseworkctl check and test, copy runtime.example.yaml to runtime.yaml and configure its database and identity settings, then create a team serving decisions as an Administrator."),
        _ => bail!("unknown template {template:?}; available templates: professional-review, standalone-decision"),
    };
    match fs::symlink_metadata(project) {
        Ok(_) => bail!("destination already exists; init never overwrites a project"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("checking the project destination"),
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
    fs::create_dir_all(staging.path().join(".casework/schemas"))?;
    fs::create_dir(staging.path().join(".vscode"))?;
    fs::write(staging.path().join("casework.yaml"), project_yaml)?;
    fs::write(
        staging.path().join("runtime.example.yaml"),
        runtime_example(project, template == "professional-review")?,
    )?;
    fs::write(
        staging.path().join(".casework/schemas/runtime.schema.json"),
        RUNTIME_SCHEMA,
    )?;
    let mut editor_settings = serde_json::to_vec_pretty(&json!({
        "yaml.schemas": {
            "./.casework/schemas/runtime.schema.json": ["runtime.example.yaml", "runtime.yaml"]
        }
    }))?;
    editor_settings.push(b'\n');
    fs::write(
        staging.path().join(".vscode/settings.json"),
        editor_settings,
    )?;
    fs::write(staging.path().join("fixtures").join(fixture_name), fixture)?;
    let staging_path = staging.keep();
    fs::rename(&staging_path, project)
        .context("publishing Casework project without replacement")?;
    Ok(json!({
        "ok": true,
        "command": "init",
        "template": template,
        "project": project,
        "created": ["casework.yaml", "runtime.example.yaml", format!("fixtures/{fixture_name}"), "sources/", ".casework/schemas/runtime.schema.json", ".vscode/settings.json"],
        "next": [next]
    }))
}

#[derive(Debug)]
pub(super) struct DeniedFindings(pub Vec<Value>);

impl std::fmt::Display for DeniedFindings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "the Casework authoring findings were denied")
    }
}

impl std::error::Error for DeniedFindings {}

fn missing_source_findings(project: &Path, policy: &CaseworkProject) -> Vec<Value> {
    policy
        .sources
        .iter()
        .enumerate()
        .filter(|(_, source)| !project.join(&source.description).is_file())
        .map(|(index, source)| json!({
            "severity": "finding",
            "code": "casework.source-description.missing",
            "artifact": "casework_project",
            "path": format!("casework.yaml:/sources/{index}/description"),
            "message": format!("source {} has no imported source description", source.id),
            "suggestedAction": format!("Run caseworkctl source add BREG_PROJECT --project {} --source-id {} --apply.", project.display(), source.id),
        }))
        .collect()
}

pub(super) fn check(project: &Path, production: bool, deny_findings: bool) -> Result<Value> {
    let policy = load_and_check_policy(project)?;
    let findings = missing_source_findings(project, &policy);
    if (production || deny_findings) && !findings.is_empty() {
        return Err(DeniedFindings(findings).into());
    }
    if policy.sources.is_empty() {
        return Ok(json!({
            "ok": true,
            "command": "check",
            "status": "complete",
            "project": project,
            "effective": {
                "projectId": policy.casework.id,
                "mode": "standalone",
                "queues": policy.queues,
                "hostedKinds": policy.hosted_kinds,
                "inbox": policy.inbox,
                "sourceConnections": 0
            },
            "profile": if production { "production" } else { "authoring" },
            "findings": findings,
            "networkAccess": false,
            "databaseAccess": false
        }));
    }
    let source_description = if findings.is_empty() {
        check_source_descriptions(project)?;
        crate::policy::check(project, &policy)?;
        "checked"
    } else {
        "pending_source_add"
    };
    let source = &policy.sources[0];
    let request = &source.requests[0];
    let inbox = serde_json::to_value(&policy.inbox)?;
    let status = if findings.is_empty() {
        "complete"
    } else {
        "incomplete"
    };
    Ok(json!({
        "ok": true,
        "command": "check",
        "status": status,
        "project": project,
        "profile": if production { "production" } else { "authoring" },
        "findings": findings,
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
    let checked = check(project, false, false)?;
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
        "authoringStatus": checked["status"],
        "findings": checked["findings"],
        "fixtures": reports,
        "proofBoundary": "offline_synthetic",
        "productionClosure": false,
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
        "runtimeConfigurationIncluded": false,
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

pub(super) fn doctor(runtime_config: &Path) -> Result<Value> {
    let config =
        RuntimeConfig::load(runtime_config).context("loading Casework runtime configuration")?;
    let runtime_config =
        fs::canonicalize(runtime_config).context("resolving Casework runtime configuration")?;
    let package_root = fs::canonicalize(&config.package.root)
        .context("resolving the configured Casework package root")?;
    check_source_descriptions(&package_root)?;
    let resolver = secret_resolver(&config).context("configuring Casework secret providers")?;
    // Resolve the audit key as a readiness check without retaining or reporting
    // its bytes. Database references are resolved inside PostgresStore.
    resolver
        .resolve(&config.audit.hash_key_ref)
        .context("the audit secret is unavailable")?;
    let runtime = async_runtime()?;
    let policy = load_and_check_policy(&package_root)?;
    if config.sources.len() != policy.sources.len() {
        bail!("operator source bindings do not exactly match the authored Casework sources");
    }
    let mut source_checks = Vec::with_capacity(policy.sources.len());
    for source in &policy.sources {
        let binding = config
            .sources
            .get(&source.id)
            .with_context(|| format!("operator source binding {} is missing", source.id))?;
        let adapter = binding
            .build_adapter(source, &package_root, &resolver)
            .with_context(|| format!("source binding {} is invalid", source.id))?;
        runtime
            .block_on(adapter.verify_reader_readiness())
            .with_context(|| {
                format!(
                    "source {} is unavailable, unready, or its configured reader lacks exact get/list access to the declared request projection or a readableRequestFields grant naming review_state",
                    source.id
                )
            })?;
        source_checks.push(doctor_source_check(&source.id));
    }
    let store = PostgresStore::connect_runtime(&config.database, &resolver)
        .context("the Casework runtime database configuration is invalid")?;
    runtime
        .block_on(store.ready())
        .context("the Casework runtime database is unavailable")?;
    runtime
        .block_on(config.oidc_verifier(&resolver))
        .context("the configured OIDC issuer is unavailable or incompatible")?;
    let expected_queue_ids: Vec<_> = policy.queues.iter().map(|queue| queue.id.clone()).collect();
    if !runtime
        .block_on(store.directory_ready(&expected_queue_ids))
        .context("checking Casework directory readiness")?
    {
        bail!("the Casework directory does not have a team serving every declared queue; authenticate as an Administrator and complete the queue assignments before retrying doctor");
    }
    Ok(json!({
        "ok": true,
        "command": "doctor",
        "runtimeConfig": runtime_config,
        "packageRoot": package_root,
        "checks": {
            "configuration": "ready",
            "sourceDescriptions": "ready",
            "sourceConnections": "ready",
            "database": "ready",
            "oidcIssuer": "ready",
            "directory": "ready"
        },
        "sourceChecks": source_checks,
        "eventWiringGuidance": EVENT_WIRING_GUIDANCE
    }))
}

fn doctor_source_check(source_id: &str) -> Value {
    json!({
        "sourceId": source_id,
        "runtime": "ready",
        "readerProfile": "ready",
        "requiredGrants": "ready",
        "eventWiring": "unknown"
    })
}

pub(super) fn db_migrate(project: &Path, runtime_config: Option<&Path>) -> Result<Value> {
    let selected = load_runtime(project, runtime_config)?;
    let config = &selected.config;
    let resolver = secret_resolver(&config).context("configuring Casework secret providers")?;
    let store = PostgresStore::connect_migration(&config.database, &resolver)
        .context("the Casework migration database configuration is invalid")?;
    async_runtime()?
        .block_on(store.migrate())
        .context("applying Casework database migrations")?;
    Ok(json!({
        "ok": true,
        "command": "db migrate",
        "project": selected.workspace,
        "runtimeConfig": selected.runtime_config,
        "status": "migrated"
    }))
}

pub(super) fn retention_erase(
    project: &Path,
    runtime_config: Option<&Path>,
    source_id: String,
    request_kind: String,
    request_id: String,
    apply: bool,
) -> Result<Value> {
    let selected = load_runtime(project, runtime_config)?;
    let config = &selected.config;
    let resolver = secret_resolver(&config).context("configuring Casework secret providers")?;
    let store = PostgresStore::connect_migration(&config.database, &resolver)
        .context("the Casework migration database configuration is invalid")?;
    let selector = SourceRetentionSelector {
        source_id,
        request_kind,
        request_id,
    };
    let runtime = async_runtime()?;
    let report = if apply {
        runtime.block_on(store.erase_source_retention(&selector))
    } else {
        runtime.block_on(store.preview_source_retention(&selector))
    }
    .context("processing Casework source retention")?;
    Ok(source_retention_output(
        &selected.workspace,
        &selected.runtime_config,
        report,
    ))
}

fn source_retention_output(
    project: &Path,
    runtime_config: &Path,
    report: SourceRetentionReport,
) -> Value {
    json!({
        "ok": true,
        "command": "retention erase",
        "project": project,
        "runtimeConfig": runtime_config,
        "report": report,
    })
}

pub(super) fn attempt_settle(
    project: &Path,
    runtime_config: Option<&Path>,
    settlement: AttemptSettlement,
    apply: bool,
) -> Result<Value> {
    let selected = load_runtime(project, runtime_config)?;
    let config = &selected.config;
    let resolver = secret_resolver(&config).context("configuring Casework secret providers")?;
    let store = PostgresStore::connect_migration(&config.database, &resolver)
        .context("the Casework migration database configuration is invalid")?;
    let runtime = async_runtime()?;
    let report = if apply {
        runtime.block_on(store.settle_attempt(&settlement))
    } else {
        runtime.block_on(store.preview_attempt_settlement(&settlement))
    }
    .context("settling the Casework source attempt")?;
    Ok(attempt_settlement_output(
        &selected.workspace,
        &selected.runtime_config,
        report,
    ))
}

fn attempt_settlement_output(
    project: &Path,
    runtime_config: &Path,
    report: AttemptSettlementReport,
) -> Value {
    json!({
        "ok": true,
        "command": "attempt settle",
        "project": project,
        "runtimeConfig": runtime_config,
        "report": report,
    })
}

pub(super) fn dev_start(project: &Path, runtime_config: Option<&Path>) -> Result<Value> {
    let workspace =
        fs::canonicalize(project).context("resolving Casework development workspace")?;
    let state = state_paths(&workspace);
    let remembered = if runtime_config.is_none() {
        read_session(&state.session)?.map(|session| session.runtime_config)
    } else {
        None
    };
    let selected = load_runtime(&workspace, runtime_config.or(remembered.as_deref()))?;
    let config = &selected.config;
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
            "--runtime-config",
            selected
                .runtime_config
                .to_str()
                .context("runtime config path is not UTF-8")?,
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
        runtime_config: selected.runtime_config.clone(),
        listen: config.listener.bind,
    };
    write_process(&state.pid, &process)?;
    write_session(
        &state.session,
        &DevSession {
            runtime_config: selected.runtime_config.clone(),
            listen: config.listener.bind,
        },
    )?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().context("checking the Casework child")? {
            let _ = fs::remove_file(&state.pid);
            bail!("Casework exited before readiness with {status}; inspect caseworkctl dev events");
        }
        if probe_ready(config.listener.bind) {
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
        "project": selected.workspace,
        "runtimeConfig": selected.runtime_config,
        "packageRoot": selected.package_root,
        "pid": process.pid,
        "listen": config.listener.bind,
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
    Ok(json!({
        "ok":true,
        "command":"dev stop",
        "project":project,
        "runtimeConfig": process.runtime_config,
        "listen": process.listen,
        "pid":process.pid,
        "status":"stopped"
    }))
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

fn runtime_config_path(project: &Path, requested: Option<&Path>) -> PathBuf {
    requested
        .map(Path::to_path_buf)
        .unwrap_or_else(|| project.join("runtime.yaml"))
}

struct RuntimeSelection {
    workspace: PathBuf,
    runtime_config: PathBuf,
    package_root: PathBuf,
    config: RuntimeConfig,
}

fn load_runtime(project: &Path, requested: Option<&Path>) -> Result<RuntimeSelection> {
    let workspace =
        fs::canonicalize(project).context("resolving Casework development workspace")?;
    let runtime_config = fs::canonicalize(runtime_config_path(&workspace, requested))
        .context("resolving Casework runtime configuration")?;
    let config =
        RuntimeConfig::load(&runtime_config).context("loading Casework runtime configuration")?;
    let package_root = fs::canonicalize(&config.package.root)
        .context("resolving the configured Casework package root")?;
    load_and_check_policy(&package_root)?;
    Ok(RuntimeSelection {
        workspace,
        runtime_config,
        package_root,
        config,
    })
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
    session: PathBuf,
    journal: PathBuf,
}

fn state_paths(project: &Path) -> StatePaths {
    let directory = project.join(".casework");
    StatePaths {
        pid: directory.join("dev-process.json"),
        session: directory.join("dev-session.json"),
        journal: directory.join("events.log"),
        directory,
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ProcessRecord {
    pid: u32,
    binary: PathBuf,
    runtime_config: PathBuf,
    listen: SocketAddr,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct DevSession {
    runtime_config: PathBuf,
    listen: SocketAddr,
}

fn read_session(path: &Path) -> Result<Option<DevSession>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .context("reading retained Casework development session"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("reading retained Casework development session"),
    }
}

fn write_session(path: &Path, session: &DevSession) -> Result<()> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().context("session path has no parent")?)?;
    serde_json::to_writer(&mut temporary, session)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
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
        && command.contains(process.runtime_config.to_string_lossy().as_ref()))
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
    fn doctor_never_reports_unattested_event_wiring_as_ready() {
        let check = doctor_source_check("professional-register");
        assert_eq!(check["sourceId"], "professional-register");
        assert_eq!(check["runtime"], "ready");
        assert_eq!(check["readerProfile"], "ready");
        assert_eq!(check["requiredGrants"], "ready");
        assert_eq!(check["eventWiring"], "unknown");
        assert!(!check.to_string().contains("eventWiring\":\"ready"));
        assert!(EVENT_WIRING_GUIDANCE.contains("bregctl doctor"));
        assert!(EVENT_WIRING_GUIDANCE.contains("confirm one lifecycle delivery"));
    }

    #[test]
    fn source_retention_output_is_count_only() {
        let output = source_retention_output(
            Path::new("/casework"),
            Path::new("/casework/runtime.yaml"),
            SourceRetentionReport {
                selector: SourceRetentionSelector {
                    source_id: "registry".into(),
                    request_kind: "correction".into(),
                    request_id: "request-1".into(),
                },
                applied: false,
                blocked_live_attempts: 1,
                items: 2,
                drafts: 3,
                correction_contexts: 4,
                attempt_payloads: 5,
                receipt_payloads: 6,
                history_details: 7,
                event_details: 8,
                idempotency_responses: 9,
                audit_records: 10,
                clock_occurrences: 11,
                clock_previews: 12,
            },
        );

        assert_eq!(output["command"], "retention erase");
        assert_eq!(output["report"]["selector"]["requestId"], "request-1");
        assert_eq!(output["report"]["blockedLiveAttempts"], 1);
        assert_eq!(output["report"]["clockOccurrences"], 11);
        assert_eq!(output["report"]["clockPreviews"], 12);
        assert_eq!(output["report"].as_object().unwrap().len(), 14);
    }

    #[test]
    fn attempt_settlement_output_reports_the_recorded_decision() {
        let attempt_id: uuid::Uuid = "7c9e6679-7425-40de-944b-e07fc1f90ae7".parse().unwrap();
        let item_id: uuid::Uuid = "16fd2706-8baf-433b-82eb-8c7fada847da".parse().unwrap();
        let output = attempt_settlement_output(
            Path::new("/casework"),
            Path::new("/casework/runtime.yaml"),
            AttemptSettlementReport {
                attempt_id,
                item_id,
                operation: registry_casework_core::OperationName::parse("approve").unwrap(),
                binding_reference: "sha256:binding".into(),
                outcome: registry_casework_core::AttemptSettlementOutcome::NotApplied,
                reason: "The source refused the saved evidence version.".into(),
                decided_by: "Registrar duty officer".into(),
                attempt_state: registry_casework_core::AttemptState::Refused,
                item_state: registry_casework_core::OccurrenceState::Claimed,
                applied: false,
            },
        );

        assert_eq!(output["ok"], true);
        assert_eq!(output["command"], "attempt settle");
        assert_eq!(output["runtimeConfig"], "/casework/runtime.yaml");
        assert_eq!(
            output["report"],
            json!({
                "attemptId": attempt_id,
                "itemId": item_id,
                "operation": "approve",
                "bindingReference": "sha256:binding",
                "outcome": "not_applied",
                "reason": "The source refused the saved evidence version.",
                "decidedBy": "Registrar duty officer",
                "attemptState": "refused",
                "itemState": "claimed",
                "applied": false,
            })
        );
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
        let checked = check(&project, false, false).unwrap();
        assert_eq!(
            load_and_check_policy(&project).unwrap().hosted_kinds,
            vec![registry_casework_core::standalone_decision_starter_kind()]
        );
        assert_eq!(checked["effective"]["mode"], "standalone");
        assert_eq!(checked["effective"]["sourceConnections"], 0);
        assert_eq!(checked["status"], "complete");
        let tested = test(&project).unwrap();
        assert_eq!(tested["authoringStatus"], "complete");
        assert_eq!(tested["findings"], json!([]));
        assert_eq!(tested["proofBoundary"], "offline_synthetic");
        assert_eq!(tested["productionClosure"], false);
        let fixture = project.join("fixtures/standalone-decision.yaml");
        let mut value = load_yaml(&fixture, "fixture").unwrap();
        value["hosted"]["display"]["undeclared"] = json!("synthetic");
        fs::write(&fixture, serde_norway::to_string(&value).unwrap()).unwrap();
        assert!(test(&project).is_err());
        let runtime = RuntimeConfig::load(project.join("runtime.example.yaml")).unwrap();
        assert!(runtime.sources.is_empty());
        assert_eq!(
            fs::read_to_string(project.join(".casework/schemas/runtime.schema.json")).unwrap(),
            RUNTIME_SCHEMA
        );
        let settings: Value =
            serde_json::from_slice(&fs::read(project.join(".vscode/settings.json")).unwrap())
                .unwrap();
        assert_eq!(
            settings["yaml.schemas"]["./.casework/schemas/runtime.schema.json"],
            json!(["runtime.example.yaml", "runtime.yaml"])
        );
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
        assert_eq!(report["runtimeConfigurationIncluded"], false);
        assert_eq!(report["secretsIncluded"], false);
        assert!(output.join("casework.yaml").is_file());
        assert!(output.join(POLICY_PACKAGE_MANIFEST_FILE).is_file());
        assert!(!output.join("runtime.example.yaml").exists());
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
    fn generated_runtime_config_loads_through_runtime_contract() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("casework.yaml"), CASEWORK_YAML).unwrap();
        fs::create_dir(directory.path().join("sources")).unwrap();
        fs::write(
            directory.path().join("sources/professional-register.json"),
            BREG_SOURCE_DESCRIPTION,
        )
        .unwrap();
        let runtime = directory.path().join("runtime.yaml");
        fs::write(&runtime, runtime_example(directory.path(), true).unwrap()).unwrap();
        let config = RuntimeConfig::load(runtime).unwrap();
        assert_eq!(config.listener.bind, "127.0.0.1:8100".parse().unwrap());
        assert!(config.sources.contains_key("professional-register"));
    }

    #[test]
    fn runtime_package_root_exclusively_selects_policy_across_workspaces() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("development-workspace");
        let selected_package = root.path().join("selected-package");
        fs::create_dir(&workspace).unwrap();
        init(&selected_package, "standalone-decision").unwrap();
        let runtime = selected_package.join("runtime.example.yaml");

        let selected = load_runtime(&workspace, Some(&runtime)).unwrap();
        assert_eq!(selected.workspace, workspace.canonicalize().unwrap());
        assert_eq!(
            selected.package_root,
            selected_package.canonicalize().unwrap()
        );
        assert_ne!(selected.workspace, selected.package_root);
        assert_eq!(
            selected.config.policy_path(),
            selected_package.join("casework.yaml")
        );
    }

    #[test]
    fn development_session_retains_runtime_config_and_listener() {
        let root = tempfile::tempdir().unwrap();
        let state = state_paths(root.path());
        fs::create_dir_all(&state.directory).unwrap();
        let session = DevSession {
            runtime_config: root.path().join("alternate-runtime.yaml"),
            listen: "127.0.0.1:8123".parse().unwrap(),
        };
        write_session(&state.session, &session).unwrap();
        let retained = read_session(&state.session).unwrap().unwrap();
        assert_eq!(retained.runtime_config, session.runtime_config);
        assert_eq!(retained.listen, session.listen);
    }

    #[test]
    fn incomplete_source_import_is_visible_and_can_be_denied() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("authored");
        init(&project, "professional-review").unwrap();

        let report = check(&project, false, false).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["status"], "incomplete");
        assert_eq!(report["findings"][0]["severity"], "finding");
        assert_eq!(
            report["findings"][0]["code"],
            "casework.source-description.missing"
        );
        assert_eq!(report["findings"][0]["artifact"], "casework_project");
        assert_eq!(
            report["findings"][0]["path"],
            "casework.yaml:/sources/0/description"
        );
        assert!(report["findings"][0]["suggestedAction"]
            .as_str()
            .unwrap()
            .contains("source add"));
        let tested = test(&project).unwrap();
        assert_eq!(tested["authoringStatus"], "incomplete");
        assert_eq!(tested["findings"], report["findings"]);
        assert_eq!(tested["proofBoundary"], "offline_synthetic");
        assert_eq!(tested["productionClosure"], false);
        assert!(check(&project, false, true)
            .unwrap_err()
            .downcast_ref::<DeniedFindings>()
            .is_some());
        assert!(check(&project, true, false)
            .unwrap_err()
            .downcast_ref::<DeniedFindings>()
            .is_some());
        assert!(package(&project, &root.path().join("package")).is_err());
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
