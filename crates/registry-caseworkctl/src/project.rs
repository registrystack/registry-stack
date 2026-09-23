// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use registry_casework::{
    secret_resolver, validate_breg_source_description, verify_policy_package,
    PolicyPackageManifest, PostgresStore, RuntimeConfig, POLICY_PACKAGE_MANIFEST_FILE,
};
use registry_casework_core::{
    AttemptSettlement, AttemptSettlementReport, CaseworkProject, ReviewContextStrategy,
    ReviewKindPurpose, SourcePolicy, SourceRequestPolicy, SourceRetentionReport,
    SourceRetentionSelector,
};
use registry_platform_config::{SecretError, SecretProvider, SecretReference, SecretResolver};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};

const CASEWORK_YAML: &str = include_str!("../templates/professional-review/casework.yaml");

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
            "scopeClaim": "scope",
            "humanIdentity": {"claim": "registry_actor_kind", "value": "human"}
        }},
        "audit": {"path": package_root.join("state/audit.ndjson"), "hashKeyRef": "secret:file/casework-audit-key"},
        "sources": {}
    });
    if include_source {
        document["sources"]["professional-licences"] = json!({
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
  "sourceId": "professional-licences",
  "sourceRevision": "sha256:source-revision",
  "request": {
    "requestEntity": "scope-correction",
    "requestRoute": "scope-corrections",
    "fields": [
      {"field":"record","apiName":"record","schema":{"type":"string","format":"uuid"}},
      {"field":"licensed-activities","apiName":"licensedActivities","schema":{"type":"array","items":{"type":"string","enum":["example-assessment","example-advisory-services","example-practical-services"]},"minItems":1,"maxItems":3,"uniqueItems":true,"x-registry-maxBytes":512}},
      {"field":"authorization-conditions","apiName":"authorizationConditions","schema":{"type":"string","minLength":0,"maxLength":500}},
      {"field":"reason","apiName":"reason","schema":{"type":"string","minLength":1,"maxLength":500}},
      {"field":"supporting-reference","apiName":"supportingReference","schema":{"type":"string","minLength":1,"maxLength":500}}
    ],
    "contractFingerprint": "sha256:contract",
    "review": {"authority":"casework-main","policyId":"scope-correction"},
    "onApproved": {"mode":"manual"},
    "application": {}
  }
}
"#;

const FIXTURE: &str = r#"apiVersion: registry.registrystack.org/casework-fixture/v1alpha1
kind: CaseworkFixture
name: professional-review-offline
source:
  id: professional-licences
  requestEntity: scope-correction
  reviewStage: review
expect:
  queue: corrections
  applicationMode: manual
  targetElapsed: PT48H
"#;

const EVENT_WIRING_GUIDANCE: &str = "The configured source reader cannot attest that BReg sends lifecycle events to this Casework receiver with the same key. Run bregctl doctor against the BReg runtime configuration, then cause and confirm one lifecycle delivery.";

pub(super) const STANDALONE_YAML: &str = r#"apiVersion: registry.registrystack.org/casework/v1alpha1
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
queues:
  - id: decisions
    label: Decisions awaiting review
reviewKinds:
  - id: decision
    version: "1"
    purpose: answer
    contextStrategy: submitted
    stages:
      - id: answer
        queue: decisions
        decidingProfiles: [staff]
        requiredApprovals: 1
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
        settlement: answered
        reasonRequired: false
      - id: rejected
        label: Return for correction
        settlement: answered
        reasonRequired: true
reviewProducers:
  - id: requester
    profile: requester
    issuer: http://127.0.0.1:8093
    subject: b75315b2-5854-70f3-8867-511dd771a6da
    sourceNamespaces: [standalone]
    kinds: [decision]
    recoveryDays: 30
"#;

const STANDALONE_FIXTURE: &str = r#"apiVersion: registry.registrystack.org/casework-fixture/v1alpha1
kind: CaseworkFixture
name: standalone-decision-offline
review:
  kind: decision
  display:
    summary: Confirm the prepared synthetic batch
    reference: synthetic-batch-0042
expect:
  queue: decisions
  outcomes: [confirmed, rejected]
"#;

/// The local clients `caseworkctl init` writes beside the standalone project.
pub(super) const STANDALONE_DEV_CLIENTS: &str = r#"# Local callers for `caseworkctl dev`. The pinned local token issuer
# that `dev` starts beside Casework, registers each client below and issues it
# short-lived tokens carrying these claims. One client binds each access
# profile `casework.yaml` declares, so a first start serves every role in the
# tutorial without another file. `registry_actor_kind: human` is the claim
# Casework requires of a person; a Requester is a calling system, so it carries
# no such claim.
#
# `dev` generates a fresh private key per client under
# `.casework/dev/credentials/`; nothing here is a credential, and none of it
# belongs in a deployment.
version: 1
clients:
  - id: administrator
    accessProfile: administrator
    scopes: [casework:admin]
    claims:
      registry_actor_kind: human
  - id: supervisor
    accessProfile: supervisor
    scopes: [casework:supervisor]
    claims:
      registry_actor_kind: human
  - id: staff
    accessProfile: staff
    scopes: [casework:staff]
    claims:
      registry_actor_kind: human
  - id: requester
    accessProfile: requester
    scopes: [casework:request]
# The directory `dev` seeds as an Administrator on the first start, so
# `caseworkctl doctor` reports ready and the inbox opens. Every queue
# `casework.yaml` declares needs a team serving it.
directory:
  - team: decisions-team
    queue: decisions
    staff: [staff]
    supervisors: [supervisor]
"#;

/// The local clients `caseworkctl init` writes beside the professional-review
/// project. That project binds a BReg source, so its runtime needs a reader
/// credential `dev` cannot generate; these clients serve a deployed runtime,
/// and the operator's own issuer provides their access tokens.
pub(super) const PROFESSIONAL_REVIEW_DEV_CLIENTS: &str = r#"# Local callers for this Casework project. Each client binds one access
# profile `casework.yaml` declares and carries the claims that profile reads:
# `registry_principal` is this project's `principalClaim`, and
# `registry_actor_kind: human` is the claim Casework requires of a person.
#
# This project binds a BReg source, so `caseworkctl dev` serves it only beside
# a running `bregctl dev` session for that registry, named with
# `--source-project`: the local session uses that registry's stock issuer
# and exports each client below as a registry client with the same
# principal, which `caseworkctl source add --apply` writes into the registry's
# own dev-clients.yaml. For a deployment, point these clients at the runtime's
# own token issuer instead.
version: 1
clients:
  - id: administrator
    accessProfile: administrator
    scopes: [casework:admin]
    claims:
      registry_actor_kind: human
      registry_principal: professional-review-administrator
  - id: supervisor
    accessProfile: supervisor
    scopes: [casework:supervisor]
    claims:
      registry_actor_kind: human
      registry_principal: professional-review-supervisor
  - id: staff
    accessProfile: staff
    scopes: [casework:staff]
    claims:
      registry_actor_kind: human
      registry_principal: professional-review-staff
  - id: integration-requester
    accessProfile: integration-requester
    scopes: [casework:reviews:request]
    claims:
      registry_principal: professional-review-breg
# Every queue `casework.yaml` declares needs a team serving it before
# `caseworkctl doctor` reports ready.
directory:
  - team: corrections-team
    queue: corrections
    staff: [staff]
    supervisors: [supervisor]
"#;

pub(super) fn init(project: &Path, template: &str) -> Result<Value> {
    let (project_yaml, fixture_name, fixture, dev_clients, next) = match template {
        "professional-review" => (CASEWORK_YAML, "professional-review.yaml", FIXTURE, PROFESSIONAL_REVIEW_DEV_CLIENTS,
            "Run caseworkctl source add with the authored BReg project and --source-id professional-licences."),
        "standalone-decision" => (STANDALONE_YAML, "standalone-decision.yaml", STANDALONE_FIXTURE, STANDALONE_DEV_CLIENTS,
            "Run caseworkctl check and test, then caseworkctl dev to start a local Casework runtime, its database and its token issuer, with the directory in dev-clients.yaml already seeded."),
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
    fs::DirBuilder::new()
        .mode(0o700)
        .create(staging.path().join(".casework"))?;
    fs::create_dir(staging.path().join(".casework/schemas"))?;
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
    fs::write(staging.path().join("dev-clients.yaml"), dev_clients)?;
    let staging_path = staging.keep();
    fs::rename(&staging_path, project)
        .context("publishing Casework project without replacement")?;
    Ok(json!({
        "ok": true,
        "command": "init",
        "template": template,
        "project": project,
        "created": ["casework.yaml", "runtime.example.yaml", "dev-clients.yaml", format!("fixtures/{fixture_name}"), "sources/", ".casework/schemas/runtime.schema.json", ".vscode/settings.json"],
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

/// One authored request, as `check` reports it.
///
/// Every value here is read from the project. A request that declares no
/// clock and no target reports `null` for both rather than a stand-in, because
/// a reader takes this block for what the engine compiled.
fn request_description(request: &SourceRequestPolicy) -> Value {
    json!({
        "entity": request.entity,
        "queue": request.queue,
        "queueMode": if request.routing.is_empty() { "default" } else { "first_match" },
        "routingRules": request.routing.len(),
        "applicationMode": "manual",
        "clock": request.clock,
        "target": request.target.as_ref().map(|target| json!({
            "id": target.id,
            "elapsed": target.after.elapsed,
        })),
    })
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
                "reviewKinds": policy.review_kinds,
                "reviewProducers": policy.review_producers,
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
    let inbox = serde_json::to_value(&policy.inbox)?;
    let sources = policy
        .sources
        .iter()
        .map(|source| {
            json!({
                "sourceId": source.id,
                "sourceAdapter": source.adapter,
                "requests": source
                    .requests
                    .iter()
                    .map(request_description)
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
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
            "sources": sources,
            "sourceDescription": source_description,
            "inbox": inbox,
            "reviewKinds": policy.review_kinds,
            "reviewProducers": policy.review_producers,
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
pub(super) fn load_and_check_policy(project: &Path) -> Result<CaseworkProject> {
    let policy = CaseworkProject::load(project.join("casework.yaml"))
        .context("loading and checking casework.yaml")?;
    if policy.sources.is_empty() {
        if policy.review_kinds.is_empty() || policy.review_producers.is_empty() {
            bail!("declare a review kind and producer or connect a source before checking the project");
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

/// The compute-only half of a policy package: everything `package` and
/// `package_dry_run` share before any filesystem write.
struct PackageContents {
    project: PathBuf,
    manifest: PolicyPackageManifest,
    inputs: Vec<(String, Vec<u8>)>,
}

/// Canonicalize the project, run every package validation, and assemble the
/// exact inputs and identity a package would carry. Performs no writes, so
/// both `package` and `package_dry_run` can share it.
fn compute_package(project: &Path) -> Result<PackageContents> {
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
    Ok(PackageContents {
        project,
        manifest,
        inputs,
    })
}

/// Report the exact `policyDigest` and `files` a package of this project
/// would carry, without writing anything.
pub(super) fn package_dry_run(project: &Path) -> Result<Value> {
    let PackageContents {
        project, manifest, ..
    } = compute_package(project)?;
    Ok(json!({
        "ok": true,
        "command": "package",
        "project": project,
        "dryRun": true,
        "policyDigest": manifest.policy_digest,
        "files": manifest.files,
        "runtimeConfigurationIncluded": false,
        "secretsIncluded": false,
        "networkAccess": false,
        "databaseAccess": false,
    }))
}

pub(super) fn package(project: &Path, output: &Path) -> Result<Value> {
    let PackageContents {
        project,
        manifest,
        inputs,
    } = compute_package(project)?;

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
        "dryRun": false,
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

pub(super) fn project_input_path(project: &Path, relative: &str) -> Result<PathBuf> {
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
    if let Some(review) = fixture.get("review") {
        let kind_id = review["kind"]
            .as_str()
            .context("review fixture requires a kind")?;
        let kind = policy
            .review_kinds
            .iter()
            .find(|kind| kind.id == kind_id)
            .context("review fixture names an undeclared kind")?;
        kind.snapshot()?
            .validate_display(&review["display"])
            .context("review fixture display does not satisfy the kind schema")?;
        let outcomes = kind
            .outcomes
            .iter()
            .map(|outcome| outcome.id.as_str())
            .collect::<Vec<_>>();
        if fixture["expect"]["queue"] != kind.stages[0].queue
            || fixture["expect"]["outcomes"] != json!(outcomes)
        {
            bail!("review fixture queue or outcomes do not match the declared kind");
        }
        return Ok(());
    }
    let source_id = fixture["source"]["id"]
        .as_str()
        .context("fixture requires a source id")?;
    let entity = fixture["source"]["requestEntity"]
        .as_str()
        .context("fixture requires a request entity")?;
    // Resolve the request the fixture names. The project may declare several
    // sources, so a fixture is checked against its own request rather than
    // against whichever one the report happens to list first.
    let source = effective["sources"]
        .as_array()
        .context("the effective project reports no sources")?
        .iter()
        .find(|source| source["sourceId"] == source_id)
        .with_context(|| {
            format!("fixture names source {source_id}, which this project does not declare")
        })?;
    let request = source["requests"]
        .as_array()
        .context("the effective source reports no requests")?
        .iter()
        .find(|request| request["entity"] == entity)
        .with_context(|| {
            format!(
                "fixture names request entity {entity}, which source {source_id} does not declare"
            )
        })?;

    let assertions = [
        (&fixture["expect"]["queue"], &request["queue"], "queue"),
        (
            &fixture["expect"]["applicationMode"],
            &request["applicationMode"],
            "application mode",
        ),
        (
            &fixture["expect"]["targetElapsed"],
            &request["target"]["elapsed"],
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

/// Every secret reference the operator configuration names, in the order an
/// operator reads them, paired with the setting that names it.
fn secret_references(config: &RuntimeConfig) -> Vec<(String, &str)> {
    let mut references = vec![
        (
            "database.runtimeUrlRef".to_owned(),
            config.database.runtime_url_ref.as_str(),
        ),
        (
            "database.migrationUrlRef".to_owned(),
            config.database.migration_url_ref.as_str(),
        ),
    ];
    if let Some(reference) = config.database.trusted_root_certificate_ref.as_deref() {
        references.push(("database.trustedRootCertificateRef".to_owned(), reference));
    }
    if let registry_casework::OidcJwksSource::Static { document_ref } =
        &config.authentication.oidc.jwks_source
    {
        references.push((
            "authentication.oidc.jwksSource.documentRef".to_owned(),
            document_ref.as_str(),
        ));
    }
    references.push((
        "audit.hashKeyRef".to_owned(),
        config.audit.hash_key_ref.as_str(),
    ));
    for (id, binding) in &config.sources {
        for (setting, reference) in [
            ("clientIdRef", Some(binding.client_id_ref.as_str())),
            (
                "clientAssertionKeyRef",
                Some(binding.client_assertion_key_ref.as_str()),
            ),
            (
                "webhookSecretRef",
                Some(binding.webhook_secret_ref.as_str()),
            ),
            (
                "trustedRootCertificatesRef",
                binding.trusted_root_certificates_ref.as_deref(),
            ),
        ] {
            if let Some(reference) = reference {
                references.push((format!("sources.{id}.{setting}"), reference));
            }
        }
    }
    for (id, destination) in &config.review_completion_destinations {
        let setting = if destination.auth.is_some() {
            "auth.secretRef"
        } else {
            "bearerTokenRef"
        };
        if let Some(reference) = destination.secret_ref() {
            references.push((
                format!("reviewCompletionDestinations.{id}.{setting}"),
                reference,
            ));
        }
    }
    references
}

/// Why one parsed file reference is unusable, or `None` when the runtime's
/// shared descriptor-relative resolver accepts it. Nothing from the resolved
/// bytes is retained or reported.
fn secret_file_refusal(
    resolver: &SecretResolver,
    reference: &SecretReference,
) -> Option<&'static str> {
    match resolver.resolve_reference(reference) {
        Ok(_) => None,
        Err(SecretError::Unavailable) => {
            Some("missing or unreadable under the configured file secret root")
        }
        Err(SecretError::UnsafeFile) => {
            Some("not an owner-only ordinary single-link file with mode 0400 or 0600")
        }
        Err(SecretError::Read) => Some("unreadable"),
        Err(SecretError::InvalidValue) => Some("not non-empty bounded text without NUL bytes"),
        Err(SecretError::InvalidReference) => Some("not a valid secret reference"),
        Err(SecretError::ProviderDisabled) => Some("served by a disabled file secret provider"),
        Err(SecretError::InvalidProviderConfiguration) => {
            Some("served by an invalid file secret provider configuration")
        }
    }
}

/// Parse every configured secret reference before the live checks, then inspect
/// each `secret:file/...` value and report one bounded result per reference. A
/// reference served by another provider is reported as outside this check
/// rather than silently omitted.
fn secret_file_checks(config: &RuntimeConfig, resolver: &SecretResolver) -> Result<Vec<Value>> {
    let file_root = config
        .secret_providers
        .file
        .as_ref()
        .map(|provider| provider.root.as_path());
    let mut checks = Vec::new();
    let mut refused = Vec::new();
    let references = secret_references(config)
        .into_iter()
        .map(|(setting, reference)| {
            SecretReference::parse(reference)
                .with_context(|| {
                    format!(
                        "{setting} must be an exact secret:env/NAME or secret:file/name reference"
                    )
                })
                .map(|reference| (setting, reference))
        })
        .collect::<Result<Vec<_>>>()?;
    for (setting, reference) in references {
        let check = match reference.provider() {
            SecretProvider::File => match secret_file_refusal(resolver, &reference) {
                None => json!({"setting": setting, "provider": "file", "status": "ready"}),
                Some(refusal) => {
                    refused.push(format!("{setting} is {refusal}"));
                    json!({"setting": setting, "provider": "file", "status": "refused", "refusal": refusal})
                }
            },
            SecretProvider::Environment => json!({
                "setting": setting,
                "provider": "environment",
                "status": "not-checked",
                "refusal": "served by the environment provider, which this check does not read"
            }),
        };
        checks.push(check);
    }
    if !refused.is_empty() {
        bail!(
            "the operator configuration names secret files this runtime cannot read: {}. Correct them under {}",
            refused.join("; "),
            file_root
                .map(|root| root.display().to_string())
                .unwrap_or_else(|| "the disabled file secret provider".to_owned())
        );
    }
    Ok(checks)
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
    let secret_files = secret_file_checks(&config, &resolver)?;
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
            "secretFiles": "ready",
            "sourceDescriptions": "ready",
            "sourceConnections": "ready",
            "database": "ready",
            "oidcIssuer": "ready",
            "directory": "ready"
        },
        "secretFileChecks": secret_files,
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
    let resolver = secret_resolver(config).context("configuring Casework secret providers")?;
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
    let resolver = secret_resolver(config).context("configuring Casework secret providers")?;
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
    let resolver = secret_resolver(config).context("configuring Casework secret providers")?;
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

fn runtime_config_path(project: &Path, requested: Option<&Path>) -> PathBuf {
    requested
        .map(Path::to_path_buf)
        .unwrap_or_else(|| project.join("runtime.yaml"))
}

struct RuntimeSelection {
    workspace: PathBuf,
    runtime_config: PathBuf,
    config: RuntimeConfig,
}

fn load_runtime(project: &Path, requested: Option<&Path>) -> Result<RuntimeSelection> {
    let workspace =
        fs::canonicalize(project).context("resolving Casework development workspace")?;
    let runtime_config = fs::canonicalize(runtime_config_path(&workspace, requested))
        .context("resolving Casework runtime configuration")?;
    let mut config =
        RuntimeConfig::load(&runtime_config).context("loading Casework runtime configuration")?;
    let package_root = fs::canonicalize(&config.package.root)
        .context("resolving the configured Casework package root")?;
    load_and_check_policy(&package_root)?;
    config.package.root = package_root;
    Ok(RuntimeSelection {
        workspace,
        runtime_config,
        config,
    })
}

fn check_source_descriptions(project: &Path) -> Result<()> {
    let policy = load_and_check_policy(project)?;
    for source in &policy.sources {
        let path = project_input_path(project, &source.description)?;
        let bytes = read_package_input(&path)?;
        validate_breg_source_description(source, &bytes).map_err(|_| {
            anyhow::anyhow!("source description {} does not match the exact BReg adapter contract bound to this source; repeat source add", path.display())
        })?;
        check_source_review_binding(&policy, source, &path, &bytes)?;
    }
    Ok(())
}

/// Confirm the pinned description's declared review policy still resolves
/// against this project's declared reviewKinds and reviewProducers,
/// mirroring the assertions `caseworkctl source add` makes when a binding is
/// first written: the named policy exists, its purpose is approval, its
/// contextStrategy is source, and casework.yaml admits at least one
/// reviewProducers[] entry whose sourceNamespaces contains this source's id
/// and whose kinds contains the pinned policy id. `source add` additionally
/// requires exactly one such entry, because it must choose the credentials it
/// pins; repinning is not what this check guards, so it accepts several.
/// `validate_breg_source_description` only confirms the description's shape
/// matches the closed BReg adapter contract; it forwards `review.policyId`
/// unchecked, so a later hand-edit of casework.yaml leaves the binding
/// broken with no signal at authoring time. Removing, renaming, or
/// repurposing the reviewKinds entry, or dropping or retargeting the
/// producer that admits this source and policy, breaks it in exactly the
/// way it breaks at runtime: the review submission names a policy Casework
/// never declared, or arrives from a producer whose kinds and
/// sourceNamespaces no longer cover it, which the Casework runtime forbids.
/// Either way it is refused and dead-letters as a permanently failed
/// background job. A second producer admitting the same pair is a different
/// fault: the runtime resolves a producer by actor identity and is
/// unaffected, but `source add` refuses to choose between two, so the
/// project can no longer be repinned by the command that wrote the binding.
///
/// This check is offline and only re-derives what the pinned description
/// already asserts about itself against the policy on disk right now. It
/// cannot detect drift in the BReg registry.yaml this description was
/// compiled from after that compilation happened: confirming that would
/// require re-deriving `sourceRevision`, which this check does not do.
/// Every refusal below names the pinned `sourceRevision` and is worded to
/// claim only that the binding is broken as pinned, never that the pin has
/// been verified current.
fn check_source_review_binding(
    policy: &CaseworkProject,
    source: &SourcePolicy,
    path: &Path,
    bytes: &[u8],
) -> Result<()> {
    let root: Value = serde_json::from_slice(bytes)
        .context("re-parsing a source description already validated as well-formed JSON")?;
    let review = &root["request"]["review"];
    if review.get("mode").and_then(Value::as_str) == Some("none") {
        return Ok(());
    }
    let source_revision = root["sourceRevision"].as_str().context(
        "source description sourceRevision was not a string despite passing description validation",
    )?;
    let policy_id = review["policyId"].as_str().context(
        "source description review.policyId was not a string despite passing description validation",
    )?;
    let source_id = source.id.as_str();
    let rendered_path = path.display();
    let Some(kind) = policy.review_kinds.iter().find(|kind| kind.id == policy_id) else {
        bail!(
            "source {source_id} description {rendered_path} pins review.policyId {policy_id:?} at sourceRevision {source_revision:?}, but casework.yaml declares no reviewKinds[].id matching {policy_id:?} as pinned; declare a reviewKinds entry with id {policy_id:?} in casework.yaml, or re-run `caseworkctl source add` to repin a policy that resolves"
        );
    };
    if kind.purpose != ReviewKindPurpose::Approval {
        bail!(
            "source {source_id} description {rendered_path} pins review.policyId {policy_id:?} at sourceRevision {source_revision:?}, which resolves to a reviewKinds entry whose purpose is not approval as pinned; set reviewKinds[].purpose to approval for {policy_id:?} in casework.yaml, or re-run `caseworkctl source add` to repin a policy that qualifies"
        );
    }
    if kind.context_strategy != ReviewContextStrategy::Source {
        bail!(
            "source {source_id} description {rendered_path} pins review.policyId {policy_id:?} at sourceRevision {source_revision:?}, which resolves to a reviewKinds entry whose contextStrategy is not source as pinned; set reviewKinds[].contextStrategy to source for {policy_id:?} in casework.yaml, or re-run `caseworkctl source add` to repin a policy that qualifies"
        );
    }
    // Mirrors the producer filter `caseworkctl source add` applies at
    // crates/registry-caseworkctl/src/source_add.rs:450-464: an admitting
    // producer is one whose sourceNamespaces contains this source's id and
    // whose kinds contains the pinned policy id. Only the filter is mirrored,
    // not `source add`'s exactly-one rule: that command has to pick the single
    // identity it writes into the description, while the runtime resolves a
    // producer by the authenticated actor's profile, issuer, and subject in
    // ReviewRuntime::producer_for_actor. Two identities admitting one source
    // and policy are a working failover pair, not a broken binding.
    let admitted = policy.review_producers.iter().any(|producer| {
        producer
            .source_namespaces
            .iter()
            .any(|namespace| namespace.as_str() == source_id)
            && producer.kinds.iter().any(|kind| kind.as_str() == policy_id)
    });
    if !admitted {
        bail!(
            "source {source_id} description {rendered_path} pins review.policyId {policy_id:?} at sourceRevision {source_revision:?}, but casework.yaml admits no reviewProducers[] entry whose sourceNamespaces includes {source_id:?} and whose kinds includes {policy_id:?} as pinned; declare a reviewProducers[] entry admitting source {source_id:?} for review kind {policy_id:?} in casework.yaml, or re-run `caseworkctl source add` to repin a policy a producer admits"
        );
    }
    Ok(())
}

fn async_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the Casework operator runtime")
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
    fn starter_display_schema_admits_every_projected_source_field() {
        let policy: CaseworkProject = serde_norway::from_str(CASEWORK_YAML).unwrap();
        let description: Value = serde_json::from_str(BREG_SOURCE_DESCRIPTION).unwrap();
        let authored = &policy.sources[0].requests[0].context_projection;
        let kind = policy
            .review_kinds
            .iter()
            .find(|kind| kind.id == "scope-correction")
            .unwrap();
        // A caller-filtered source read discloses each projected field under
        // its API name, and preflight validates that map against the kind's
        // displaySchema; a closed schema that admits none of them conceals
        // every source-backed task.
        let mut disclosed = serde_json::Map::new();
        for field in description["request"]["fields"].as_array().unwrap() {
            if !authored
                .iter()
                .any(|name| name == field["field"].as_str().unwrap())
            {
                continue;
            }
            // The template restates each projected field's source schema,
            // so a value the source accepts is a value the kind displays.
            assert_eq!(
                kind.display_schema["properties"][field["apiName"].as_str().unwrap()],
                field["schema"],
                "displaySchema restates the source schema of {}",
                field["field"]
            );
            let sample = match field["apiName"].as_str().unwrap() {
                "record" => json!("0f8b6c1e-2d4a-4c3b-9a7e-5b1d2c3e4f60"),
                "licensedActivities" => json!(["example-assessment"]),
                "authorizationConditions" => json!("Scope changes need a supervisor decision."),
                "supportingReference" => json!("correction-case-1189"),
                other => panic!("the starter projects unknown field {other:?}"),
            };
            disclosed.insert(field["apiName"].as_str().unwrap().to_owned(), sample);
        }
        assert_eq!(disclosed.len(), authored.len());
        kind.snapshot()
            .unwrap()
            .validate_display(&Value::Object(disclosed))
            .unwrap();
    }

    #[test]
    fn starter_producer_subject_matches_its_dev_client_principal() {
        let policy: CaseworkProject = serde_norway::from_str(CASEWORK_YAML).unwrap();
        let clients: Value = serde_norway::from_str(PROFESSIONAL_REVIEW_DEV_CLIENTS).unwrap();
        for producer in &policy.review_producers {
            let profile = &policy
                .access_profiles
                .iter()
                .find(|profile| profile.id == producer.profile)
                .unwrap();
            let client = clients["clients"]
                .as_array()
                .unwrap()
                .iter()
                .find(|client| client["accessProfile"].as_str() == Some(profile.id.as_str()))
                .unwrap();
            // The dev flow exports this client with the same principal claim
            // to the shared BReg stock issuer, and Casework admits the
            // requester only when the producer's subject is exactly that
            // claim value.
            assert_eq!(
                client["claims"][profile.principal_claim.as_str()].as_str(),
                Some(producer.subject.as_str()),
                "producer {} does not match its dev client principal",
                producer.id
            );
        }
    }

    #[test]
    fn starter_review_excludes_the_person_who_submitted_the_request() {
        let policy: CaseworkProject = serde_norway::from_str(CASEWORK_YAML).unwrap();
        policy.check().unwrap();
        for kind in &policy.review_kinds {
            for stage in &kind.stages {
                assert!(
                    stage.exclude_initiator,
                    "stage {} of {} lets a submitter approve their own request",
                    stage.id, kind.id
                );
            }
        }
        // BReg names the initiator with its stock issuer and the same
        // principal claim these profiles read, so the producer trusts
        // initiators from the issuer it authenticates with.
        for producer in &policy.review_producers {
            assert_eq!(
                producer.trusted_initiator_issuer.as_deref(),
                Some(producer.issuer.as_str()),
                "producer {} does not trust its own issuer for initiators",
                producer.id
            );
        }
        let principal_claims = policy
            .access_profiles
            .iter()
            .map(|profile| profile.principal_claim.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            principal_claims,
            ["registry_principal"].into_iter().collect(),
            "an initiator matches a reviewer only when both read one principal claim"
        );
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
        let effective = json!({"sources":[{"sourceId":"professional-licences","requests":[
            {"entity":"scope-correction","queue":"corrections","applicationMode":"manual","target":{"elapsed":"PT48H"}}
        ]}]});
        validate_fixture(
            &fixture,
            &effective,
            &serde_norway::from_str(CASEWORK_YAML).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn init_writes_local_clients_for_both_templates() {
        for (template, queue, profiles) in [
            (
                "standalone-decision",
                "decisions",
                vec!["administrator", "supervisor", "staff", "requester"],
            ),
            (
                "professional-review",
                "corrections",
                vec![
                    "administrator",
                    "supervisor",
                    "staff",
                    "integration-requester",
                ],
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let project = root.path().join(template);
            let report = init(&project, template).unwrap();
            assert!(report["created"]
                .as_array()
                .unwrap()
                .contains(&json!("dev-clients.yaml")));
            let clients = project.join("dev-clients.yaml");
            let text = fs::read_to_string(&clients).unwrap();
            let value: Value = serde_norway::from_str(&text).unwrap();
            assert_eq!(value["version"], 1);
            let runtime: Value = serde_norway::from_str(
                &fs::read_to_string(project.join("runtime.example.yaml")).unwrap(),
            )
            .unwrap();
            assert_eq!(runtime["authentication"]["oidc"]["scopeClaim"], "scope");
            let declared: Vec<&str> = value["clients"]
                .as_array()
                .unwrap()
                .iter()
                .map(|client| client["accessProfile"].as_str().unwrap())
                .collect();
            assert_eq!(declared, profiles);
            assert_eq!(value["directory"][0]["queue"], queue);
            // The file explains itself; none of it is a credential.
            assert!(text.starts_with('#'), "{template}");
            // Every profile the project declares is bound exactly once.
            let policy = load_and_check_policy(&project).unwrap();
            let bound: Vec<&str> = policy
                .access_profiles
                .iter()
                .map(|profile| profile.id.as_str())
                .collect();
            assert_eq!(
                bound
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>(),
                declared
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
            );
        }
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        init(&project, "standalone-decision").unwrap();
        assert!(init(&project, "standalone-decision").is_err());
    }

    #[test]
    fn the_secret_file_preflight_names_every_unusable_reference() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let secrets = root.path().to_path_buf();
        let write = |name: &str, bytes: &[u8], mode: u32| {
            let path = secrets.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        };
        write("ready", b"0123456789abcdef", 0o600);
        write("readable", b"0123456789abcdef", 0o644);
        write("empty", b"", 0o600);
        write("with-nul", b"abc\0def", 0o600);
        write(
            "at-limit",
            &vec![b'x'; registry_platform_config::MAX_SECRET_BYTES],
            0o600,
        );
        write(
            "over-limit",
            &vec![b'x'; registry_platform_config::MAX_SECRET_BYTES + 1],
            0o600,
        );

        let resolver = SecretResolver::new([SecretProvider::File], &secrets).unwrap();
        let refusal = |name: &str| {
            let reference = SecretReference::parse(format!("secret:file/{name}")).unwrap();
            secret_file_refusal(&resolver, &reference)
        };
        assert_eq!(refusal("ready"), None);
        assert_eq!(
            refusal("absent"),
            Some("missing or unreadable under the configured file secret root")
        );
        assert_eq!(
            refusal("readable"),
            Some("not an owner-only ordinary single-link file with mode 0400 or 0600")
        );
        assert_eq!(
            refusal("empty"),
            Some("not non-empty bounded text without NUL bytes")
        );
        assert_eq!(refusal("at-limit"), None);
        assert_eq!(
            refusal("over-limit"),
            Some("not non-empty bounded text without NUL bytes")
        );
        assert_eq!(
            refusal("with-nul"),
            Some("not non-empty bounded text without NUL bytes")
        );
    }

    #[test]
    fn the_secret_file_preflight_reports_one_result_per_reference() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        init(&project, "standalone-decision").unwrap();
        let secrets = project.join("secrets");
        fs::create_dir(&secrets).unwrap();
        let audit = secrets.join("casework-audit-key");
        fs::write(&audit, "0".repeat(64)).unwrap();
        fs::set_permissions(&audit, fs::Permissions::from_mode(0o600)).unwrap();
        let runtime_config = project.join("runtime.example.yaml");
        let mut document: Value =
            serde_norway::from_str(&runtime_example(&project, false).unwrap()).unwrap();
        document["secretProviders"]["environment"] = json!({});
        document["database"]["runtimeUrlRef"] = json!("secret:env/CASEWORK_DATABASE_URL");
        document["database"]["migrationUrlRef"] =
            json!("secret:env/CASEWORK_MIGRATION_DATABASE_URL");
        fs::write(&runtime_config, serde_norway::to_string(&document).unwrap()).unwrap();
        let config = RuntimeConfig::load(&runtime_config).unwrap();
        let resolver = secret_resolver(&config).unwrap();

        let checks = secret_file_checks(&config, &resolver).unwrap();
        let settings: Vec<&str> = checks
            .iter()
            .map(|check| check["setting"].as_str().unwrap())
            .collect();
        assert_eq!(
            settings,
            [
                "database.runtimeUrlRef",
                "database.migrationUrlRef",
                "audit.hashKeyRef"
            ]
        );
        // The example binds its database through the environment provider.
        assert_eq!(checks[0]["provider"], "environment");
        assert_eq!(checks[0]["status"], "not-checked");
        assert_eq!(checks[2]["provider"], "file");
        assert_eq!(checks[2]["status"], "ready");
        // No result may carry any part of a secret.
        assert!(!serde_json::to_string(&checks).unwrap().contains("00000"));

        fs::set_permissions(&audit, fs::Permissions::from_mode(0o644)).unwrap();
        let refusal = format!("{:#}", secret_file_checks(&config, &resolver).unwrap_err());
        assert!(refusal.contains("audit.hashKeyRef"), "{refusal}");
        assert!(refusal.contains("0400 or 0600"), "{refusal}");
    }

    #[test]
    fn the_secret_file_preflight_checks_completion_destination_secrets() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        init(&project, "standalone-decision").unwrap();
        let secrets = project.join("secrets");
        fs::create_dir(&secrets).unwrap();
        for name in ["casework-audit-key", "receiver-token", "notifier-key"] {
            let path = secrets.join(name);
            fs::write(&path, "0".repeat(64)).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let runtime_config = project.join("runtime.example.yaml");
        let mut document: Value =
            serde_norway::from_str(&runtime_example(&project, false).unwrap()).unwrap();
        document["secretProviders"]["environment"] = json!({});
        document["database"]["runtimeUrlRef"] = json!("secret:env/CASEWORK_DATABASE_URL");
        document["database"]["migrationUrlRef"] =
            json!("secret:env/CASEWORK_MIGRATION_DATABASE_URL");
        document["reviewCompletionDestinations"] = json!({
            "receiver": {
                "url": "https://completion.example.test/v1/reviews",
                "bearerTokenRef": "secret:file/receiver-token"
            },
            "notifier": {
                "url": "https://notifier.example.test/v1/reviews",
                "auth": {"header": "X-Api-Key", "secretRef": "secret:file/notifier-key"}
            }
        });
        fs::write(&runtime_config, serde_norway::to_string(&document).unwrap()).unwrap();
        let config = RuntimeConfig::load(&runtime_config).unwrap();
        let resolver = secret_resolver(&config).unwrap();

        let checks = secret_file_checks(&config, &resolver).unwrap();
        let settings: Vec<&str> = checks
            .iter()
            .map(|check| check["setting"].as_str().unwrap())
            .collect();
        assert_eq!(
            settings,
            [
                "database.runtimeUrlRef",
                "database.migrationUrlRef",
                "audit.hashKeyRef",
                "reviewCompletionDestinations.notifier.auth.secretRef",
                "reviewCompletionDestinations.receiver.bearerTokenRef"
            ]
        );
        assert_eq!(checks[3]["status"], "ready");
        assert_eq!(checks[4]["status"], "ready");

        fs::set_permissions(
            secrets.join("notifier-key"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let refusal = format!("{:#}", secret_file_checks(&config, &resolver).unwrap_err());
        assert!(
            refusal.contains("reviewCompletionDestinations.notifier.auth.secretRef"),
            "{refusal}"
        );
        assert!(!refusal.contains("receiver"), "{refusal}");
    }

    #[test]
    fn doctor_refuses_a_symlinked_file_root_for_a_migration_only_file_reference() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        init(&project, "standalone-decision").unwrap();
        let actual_secrets = root.path().join("actual-secrets");
        fs::create_dir(&actual_secrets).unwrap();
        let migration = actual_secrets.join("migration-database-url");
        fs::write(&migration, "postgresql://migration.example.test/casework").unwrap();
        fs::set_permissions(&migration, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&actual_secrets, project.join("secrets")).unwrap();
        let runtime_config = project.join("runtime.example.yaml");
        let mut document: Value =
            serde_norway::from_str(&runtime_example(&project, false).unwrap()).unwrap();
        document["secretProviders"]["environment"] = json!({});
        document["audit"]["hashKeyRef"] = json!("secret:env/CASEWORK_AUDIT_KEY");
        fs::write(&runtime_config, serde_norway::to_string(&document).unwrap()).unwrap();
        let config = RuntimeConfig::load(&runtime_config).unwrap();
        let resolver = secret_resolver(&config).unwrap();
        let migration = SecretReference::parse(&config.database.migration_url_ref).unwrap();

        assert_eq!(
            resolver.resolve_reference(&migration).unwrap_err(),
            SecretError::Unavailable
        );
        let refusal = format!("{:#}", doctor(&runtime_config).unwrap_err());
        assert!(refusal.contains("database.migrationUrlRef"), "{refusal}");
        assert!(
            refusal.contains("missing or unreadable under the configured file secret root"),
            "{refusal}"
        );
    }

    #[test]
    fn doctor_refuses_malformed_secret_references_before_live_checks() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        init(&project, "standalone-decision").unwrap();
        let secrets = project.join("secrets");
        fs::create_dir(&secrets).unwrap();
        let audit = secrets.join("casework-audit-key");
        fs::write(&audit, "0".repeat(64)).unwrap();
        fs::set_permissions(&audit, fs::Permissions::from_mode(0o600)).unwrap();
        let runtime_config = project.join("runtime.example.yaml");
        let mut document: Value =
            serde_norway::from_str(&runtime_example(&project, false).unwrap()).unwrap();
        document["secretProviders"]["environment"] = json!({});
        document["database"]["runtimeUrlRef"] = json!("secret:env/CASEWORK_DATABASE_URL");
        document["database"]["migrationUrlRef"] =
            json!("secret:env/CASEWORK_MIGRATION_DATABASE_URL");
        let valid = serde_norway::to_string(&document).unwrap();

        for (setting, authored, malformed) in [
            (
                "database.runtimeUrlRef",
                "secret:env/CASEWORK_DATABASE_URL",
                "CASEWORK_DATABASE_URL",
            ),
            (
                "database.migrationUrlRef",
                "secret:env/CASEWORK_MIGRATION_DATABASE_URL",
                "secret:file/../token",
            ),
        ] {
            fs::write(&runtime_config, valid.replace(authored, malformed)).unwrap();

            let error = doctor(&runtime_config).unwrap_err();
            let runtime_error = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<registry_casework::RuntimeConfigError>());
            assert!(
                matches!(
                    runtime_error,
                    Some(registry_casework::RuntimeConfigError::InvalidSecretReference { path })
                        if path == setting
                ),
                "{error:#}"
            );
            let refusal = format!("{error:#}");
            assert!(
                refusal.contains(&format!("{setting} is not a valid secret reference")),
                "{refusal}"
            );
            assert!(!refusal.contains(malformed), "{refusal}");
        }
    }

    #[test]
    fn doctor_refuses_a_completion_secret_in_a_reserved_header() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        init(&project, "standalone-decision").unwrap();
        let runtime_config = project.join("runtime.example.yaml");
        let mut document: Value =
            serde_norway::from_str(&runtime_example(&project, false).unwrap()).unwrap();
        document["reviewCompletionDestinations"] = json!({
            "receiver": {
                "url": "https://completion.example.test/v1/reviews",
                "auth": {"header": "Host", "secretRef": "secret:file/completion-key"}
            }
        });
        fs::write(&runtime_config, serde_norway::to_string(&document).unwrap()).unwrap();

        let error = doctor(&runtime_config).unwrap_err();
        let runtime_error = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<registry_casework::RuntimeConfigError>());
        assert!(
            matches!(
                runtime_error,
                Some(registry_casework::RuntimeConfigError::InvalidReviewCompletionAuth { path })
                    if path == "reviewCompletionDestinations.receiver.auth.header"
            ),
            "{error:#}"
        );
    }

    #[test]
    fn standalone_starter_checks_real_review_display_schema_without_a_source() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        init(&project, "standalone-decision").unwrap();
        assert_eq!(
            fs::metadata(project.join(".casework"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "dev state must be created under an owner-only parent"
        );
        let checked = check(&project, false, false).unwrap();
        assert_eq!(
            load_and_check_policy(&project).unwrap().review_kinds.len(),
            1
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
        value["review"]["display"]["undeclared"] = json!("synthetic");
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
            project.join("sources/professional-licences.json"),
            BREG_SOURCE_DESCRIPTION,
        )
        .unwrap();

        package(&project, &output).unwrap();
        assert!(output.join("sources/professional-licences.json").is_file());
        let policy = CaseworkProject::load(output.join("casework.yaml")).unwrap();
        assert!(
            verify_policy_package(&output.join("casework.yaml"), &policy)
                .unwrap()
                .is_some()
        );
        fs::write(output.join("sources/professional-licences.json"), "{}\n").unwrap();
        assert!(verify_policy_package(&output.join("casework.yaml"), &policy).is_err());
    }

    #[test]
    fn package_dry_run_reports_the_same_digest_without_writing() {
        fn count_files(dir: &Path) -> usize {
            let mut count = 0;
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    count += count_files(&path);
                } else {
                    count += 1;
                }
            }
            count
        }

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        init(&project, "standalone-decision").unwrap();
        let files_before = count_files(&project);

        let output = root.path().join("package");
        let dry = package_dry_run(&project).unwrap();
        assert_eq!(dry["command"], "package");
        assert_eq!(dry["dryRun"], true);
        assert!(dry["policyDigest"].as_str().unwrap().starts_with("sha256:"));
        assert!(dry.get("output").is_none());
        assert!(!output.exists());
        assert_eq!(count_files(&project), files_before);

        let real = package(&project, &output).unwrap();
        assert_eq!(real["dryRun"], false);
        assert_eq!(real["policyDigest"], dry["policyDigest"]);
        assert_eq!(real["files"], dry["files"]);
    }

    #[test]
    fn package_dry_run_still_refuses_an_invalid_project() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("standalone");
        init(&project, "standalone-decision").unwrap();
        let actual_policy = root.path().join("actual-casework.yaml");
        fs::rename(project.join("casework.yaml"), &actual_policy).unwrap();
        std::os::unix::fs::symlink(&actual_policy, project.join("casework.yaml")).unwrap();

        let output = root.path().join("package");
        let real_error = format!("{:#}", package(&project, &output).unwrap_err());
        let dry_run_error = format!("{:#}", package_dry_run(&project).unwrap_err());
        assert_eq!(real_error, dry_run_error);
        assert!(dry_run_error.contains("regular file"), "{dry_run_error}");
        assert!(!output.exists());
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
            directory.path().join("sources/professional-licences.json"),
            BREG_SOURCE_DESCRIPTION,
        )
        .unwrap();
        let runtime = directory.path().join("runtime.yaml");
        fs::write(&runtime, runtime_example(directory.path(), true).unwrap()).unwrap();
        let config = RuntimeConfig::load(runtime).unwrap();
        assert_eq!(config.listener.bind, "127.0.0.1:8100".parse().unwrap());
        assert!(config.sources.contains_key("professional-licences"));
    }

    // registrystack/registry-stack#1256: a pinned BReg source description
    // may name a review.policyId that resolves to no declared reviewKinds
    // entry (or to one that cannot actually accept the submission). Nothing
    // refused that at authoring time; the review request would instead be
    // accepted and its background submission would silently dead-letter.
    // `write_offline_project` reuses the same CASEWORK_YAML / BREG_SOURCE_DESCRIPTION
    // fixture pair other tests in this module already build offline projects from.
    fn write_offline_project(
        casework_yaml: &str,
        description: &str,
    ) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("authored");
        fs::create_dir_all(project.join("sources")).unwrap();
        fs::write(project.join("casework.yaml"), casework_yaml).unwrap();
        fs::write(
            project.join("sources/professional-licences.json"),
            description,
        )
        .unwrap();
        (root, project)
    }

    #[test]
    fn check_source_descriptions_refuses_an_unresolved_review_policy_id() {
        let mut description: Value = serde_json::from_str(BREG_SOURCE_DESCRIPTION).unwrap();
        description["request"]["review"]["policyId"] = json!("missing-review-kind");
        let description = serde_json::to_string(&description).unwrap();
        let (_root, project) = write_offline_project(CASEWORK_YAML, &description);

        let error = format!("{:#}", check_source_descriptions(&project).unwrap_err());
        assert!(error.contains("missing-review-kind"), "{error}");
        assert!(error.contains("sha256:source-revision"), "{error}");
    }

    #[test]
    fn check_source_descriptions_accepts_a_no_review_description_with_no_declared_review_kinds() {
        let no_review_kinds_yaml = CASEWORK_YAML.split("reviewKinds:\n").next().unwrap();
        let mut description: Value = serde_json::from_str(BREG_SOURCE_DESCRIPTION).unwrap();
        description["request"]["review"] = json!({"mode": "none"});
        let description = serde_json::to_string(&description).unwrap();
        let (_root, project) = write_offline_project(no_review_kinds_yaml, &description);

        check_source_descriptions(&project).unwrap();
    }

    #[test]
    fn check_source_descriptions_accepts_a_policy_id_that_resolves_to_a_declared_kind() {
        let (_root, project) = write_offline_project(CASEWORK_YAML, BREG_SOURCE_DESCRIPTION);

        check_source_descriptions(&project).unwrap();
    }

    #[test]
    fn check_source_descriptions_refuses_a_resolved_kind_with_the_wrong_context_strategy() {
        let wrong_context_yaml =
            CASEWORK_YAML.replace("contextStrategy: source", "contextStrategy: submitted");
        let (_root, project) = write_offline_project(&wrong_context_yaml, BREG_SOURCE_DESCRIPTION);

        let error = format!("{:#}", check_source_descriptions(&project).unwrap_err());
        assert!(error.contains("contextStrategy"), "{error}");
        assert!(error.contains("scope-correction"), "{error}");
        assert!(!error.contains("no declared reviewKinds"), "{error}");
    }

    #[test]
    fn check_source_descriptions_refuses_a_resolved_kind_with_the_wrong_purpose() {
        // Swapping purpose alone would trip registry-casework-core's own
        // AnswerOutcomes rule (an Answer-purpose kind needs a non-empty,
        // all-Answered outcomes list) before this check ever ran, so the
        // fixture also settles the template's one outcome as answered, the
        // minimal list that satisfies core's rule, and keeps the fixture on
        // the purpose branch this test targets.
        let wrong_purpose_yaml = CASEWORK_YAML
            .replace("purpose: approval", "purpose: answer")
            .replace("settlement: changes_requested", "settlement: answered");
        let (_root, project) = write_offline_project(&wrong_purpose_yaml, BREG_SOURCE_DESCRIPTION);

        let error = format!("{:#}", check_source_descriptions(&project).unwrap_err());
        assert!(error.contains("purpose"), "{error}");
        assert!(error.contains("scope-correction"), "{error}");
        assert!(!error.contains("no declared reviewKinds"), "{error}");
    }

    // A second reviewKinds entry, structurally identical to scope-correction's,
    // so a producer's `kinds` can reference a real declared kind that is not
    // the pinned policy id. registry-casework-core's own checks require every
    // reviewProducers[].kinds[] entry to resolve to a declared reviewKinds
    // entry, so a bogus kind id cannot stand in for this.
    const OTHER_REVIEW_KIND_YAML: &str = r#"
  - id: other-review
    version: "1"
    purpose: approval
    contextStrategy: source
    stages:
      - id: review
        queue: corrections
        decidingProfiles: [staff]
        requiredApprovals: 1
    retention:
      terminalDays: 30
      accountabilityDays: 365
    displaySchema:
      type: object
      additionalProperties: false
      properties: {}
"#;

    #[test]
    fn check_source_descriptions_refuses_when_no_producer_admits_this_source_namespace() {
        // The only reviewProducers entry is renamed away from this source's
        // id, the same shape as a producer being dropped outright: either
        // way, zero producers admit this source and policy pair.
        let renamed_namespace_yaml = CASEWORK_YAML.replace(
            "sourceNamespaces: [professional-licences]",
            "sourceNamespaces: [other-source]",
        );
        let (_root, project) =
            write_offline_project(&renamed_namespace_yaml, BREG_SOURCE_DESCRIPTION);

        let error = format!("{:#}", check_source_descriptions(&project).unwrap_err());
        assert!(error.contains("admits no reviewProducers"), "{error}");
        assert!(error.contains("professional-licences"), "{error}");
        assert!(error.contains("scope-correction"), "{error}");
        assert!(error.contains("sha256:source-revision"), "{error}");
    }

    #[test]
    fn check_source_descriptions_refuses_when_no_producer_admits_this_review_kind() {
        // The only reviewProducers entry still admits the source namespace,
        // but its kinds[] now points at a different declared reviewKinds
        // entry instead of the pinned policy id, so zero producers admit
        // this source and policy pair.
        let retargeted_kind_yaml = CASEWORK_YAML
            .replacen(
                "reviewProducers:\n",
                &format!("{OTHER_REVIEW_KIND_YAML}reviewProducers:\n"),
                1,
            )
            .replace("kinds: [scope-correction]", "kinds: [other-review]");
        let (_root, project) =
            write_offline_project(&retargeted_kind_yaml, BREG_SOURCE_DESCRIPTION);

        let error = format!("{:#}", check_source_descriptions(&project).unwrap_err());
        assert!(error.contains("admits no reviewProducers"), "{error}");
        assert!(error.contains("professional-licences"), "{error}");
        assert!(error.contains("scope-correction"), "{error}");
    }

    #[test]
    fn check_source_descriptions_accepts_two_producer_identities_for_one_source_and_policy() {
        // A second reviewProducers entry admits the same sourceNamespaces and
        // kinds under a distinct id and subject: a failover integration beside
        // the primary one. The runtime resolves a producer by the authenticated
        // actor's profile, issuer, and subject, never by uniqueness, so both
        // identities submit under the same pinned policy and neither shadows
        // the other. Only `source add` needs exactly one, because it must pick
        // the credentials it writes into the description.
        let second_identity_yaml = CASEWORK_YAML.replace(
            "    sourceNamespaces: [professional-licences]\n    kinds: [scope-correction]\n    recoveryDays: 7\n",
            "    sourceNamespaces: [professional-licences]\n    kinds: [scope-correction]\n    recoveryDays: 7\n  - id: registry-breg-failover\n    profile: integration-requester\n    issuer: http://127.0.0.1:8091\n    subject: professional-review-breg-failover\n    trustedInitiatorIssuer: http://127.0.0.1:8091\n    sourceNamespaces: [professional-licences]\n    kinds: [scope-correction]\n    recoveryDays: 7\n",
        );
        let (_root, project) =
            write_offline_project(&second_identity_yaml, BREG_SOURCE_DESCRIPTION);

        check_source_descriptions(&project).unwrap();
    }

    #[test]
    fn check_source_descriptions_accepts_the_producer_bound_to_this_source_and_policy_among_others()
    {
        // A second reviewProducers entry admits a different source
        // namespace, proving the check selects the one producer actually
        // bound to this source and policy rather than merely counting
        // producers overall.
        let extra_producer_yaml = CASEWORK_YAML.replace(
            "    recoveryDays: 7\n",
            "    recoveryDays: 7\n  - id: registry-breg-other\n    profile: integration-requester\n    issuer: http://127.0.0.1:8091\n    subject: professional-review-breg-other\n    trustedInitiatorIssuer: http://127.0.0.1:8091\n    sourceNamespaces: [other-source]\n    kinds: [scope-correction]\n    recoveryDays: 7\n",
        );
        let (_root, project) = write_offline_project(&extra_producer_yaml, BREG_SOURCE_DESCRIPTION);

        check_source_descriptions(&project).unwrap();
    }

    #[test]
    fn explain_refuses_the_same_unresolved_review_binding_as_check() {
        let mut description: Value = serde_json::from_str(BREG_SOURCE_DESCRIPTION).unwrap();
        description["request"]["review"]["policyId"] = json!("missing-review-kind");
        let description = serde_json::to_string(&description).unwrap();
        let (_root, project) = write_offline_project(CASEWORK_YAML, &description);

        let error = format!("{:#}", explain(&project).unwrap_err());
        assert!(error.contains("missing-review-kind"), "{error}");
    }

    #[test]
    fn explain_reports_the_review_model_queues_and_access_profiles() {
        let (_root, project) = write_offline_project(CASEWORK_YAML, BREG_SOURCE_DESCRIPTION);

        let explained = explain(&project).unwrap();

        assert_eq!(explained["queues"][0]["id"], "corrections");
        assert_eq!(explained["queues"][0]["label"], "Licence corrections");
        assert_eq!(
            explained["accessProfiles"]
                .as_array()
                .unwrap()
                .iter()
                .map(|profile| profile["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "staff",
                "supervisor",
                "administrator",
                "integration-requester"
            ]
        );
        let kind = &explained["reviewKinds"][0];
        assert_eq!(kind["id"], "scope-correction");
        assert_eq!(kind["purpose"], "approval");
        assert_eq!(kind["contextStrategy"], "source");
        assert_eq!(kind["stages"][0]["queue"], "corrections");
        assert_eq!(kind["stages"][0]["decidingProfiles"][0], "staff");
        assert_eq!(kind["stages"][0]["requiredApprovals"], 1);
    }

    #[test]
    fn explain_preserves_authored_stage_and_outcome_order() {
        let two_stage_yaml = CASEWORK_YAML.replace(
            "        requiredApprovals: 1\n    outcomes:\n",
            "        requiredApprovals: 1\n      - id: endorsement\n        queue: corrections\n        decidingProfiles: [supervisor]\n        requiredApprovals: 2\n        excludePreviousStageReviewers: true\n    outcomes:\n      - id: refused\n        label: Refused\n        settlement: rejected\n        reasonRequired: true\n",
        );
        let (_root, project) = write_offline_project(&two_stage_yaml, BREG_SOURCE_DESCRIPTION);

        let kind = explain(&project).unwrap()["reviewKinds"][0].clone();

        assert_eq!(
            kind["stages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|stage| stage["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["review", "endorsement"],
            "stage order decides who reviews first and must survive the report"
        );
        assert_eq!(kind["stages"][1]["excludePreviousStageReviewers"], true);
        assert_eq!(
            kind["outcomes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|outcome| outcome["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["refused", "changes-requested"]
        );
        assert_eq!(kind["outcomes"][1]["settlement"], "changes_requested");
    }

    #[test]
    fn check_reports_the_initiator_profile_and_refuses_one_that_is_not_a_requester() {
        let with_initiator = CASEWORK_YAML
            .replace(
                "sources:\n",
                "  - id: change-submitter\n    principalClaim: registry_principal\n    requiredScopes: [casework:reviews:history]\n    role: requester\nsources:\n",
            )
            .replace(
                "    subject: professional-review-breg\n",
                "    subject: professional-review-breg\n    initiatorProfile: change-submitter\n",
            );
        let (_root, project) = write_offline_project(&with_initiator, BREG_SOURCE_DESCRIPTION);
        let effective = check(&project, false, false).unwrap()["effective"].clone();
        assert_eq!(
            effective["reviewProducers"][0]["initiatorProfile"],
            "change-submitter"
        );

        let staff_initiator = CASEWORK_YAML.replace(
            "    subject: professional-review-breg\n",
            "    subject: professional-review-breg\n    initiatorProfile: staff\n",
        );
        let (_root, project) = write_offline_project(&staff_initiator, BREG_SOURCE_DESCRIPTION);
        let refused = format!("{:#}", check(&project, false, false).unwrap_err());
        assert!(
            refused.contains("reviewProducers[0].initiatorProfile"),
            "{refused}"
        );
    }

    #[test]
    fn source_backed_check_reports_review_kinds_and_their_producers() {
        let (_root, project) = write_offline_project(CASEWORK_YAML, BREG_SOURCE_DESCRIPTION);

        let effective = check(&project, false, false).unwrap()["effective"].clone();

        assert_eq!(effective["sources"][0]["sourceId"], "professional-licences");
        assert_eq!(effective["reviewKinds"][0]["id"], "scope-correction");
        assert_eq!(
            effective["reviewKinds"][0]["stages"][0]["queue"],
            "corrections"
        );
        assert_eq!(effective["reviewProducers"][0]["id"], "registry-breg");
        assert_eq!(
            effective["reviewProducers"][0]["kinds"][0],
            "scope-correction"
        );
        assert_eq!(
            effective["reviewProducers"][0]["sourceNamespaces"][0],
            "professional-licences"
        );
    }
    /// A project with a second source, so a report that only ever describes
    /// `sources[0]` is visibly wrong rather than plausibly right.
    fn write_two_source_project() -> (tempfile::TempDir, PathBuf) {
        let mut policy: serde_norway::Value = serde_norway::from_str(CASEWORK_YAML).unwrap();
        let sources = policy["sources"].as_sequence_mut().unwrap();
        let mut second = sources[0].clone();
        second["id"] = "response-register".into();
        second["description"] = "sources/response-register.json".into();
        second["requests"][0]["entity"] = "response-correction".into();
        second["requests"][0]["target"]["id"] = "response-window".into();
        second["requests"][0]["target"]["after"]["elapsed"] = "PT72H".into();
        sources.push(second);
        policy["reviewProducers"][0]["sourceNamespaces"]
            .as_sequence_mut()
            .unwrap()
            .push("response-register".into());

        let mut description: Value = serde_json::from_str(BREG_SOURCE_DESCRIPTION).unwrap();
        description["sourceId"] = json!("response-register");
        description["request"]["requestEntity"] = json!("response-correction");

        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("authored");
        fs::create_dir_all(project.join("sources")).unwrap();
        fs::write(
            project.join("casework.yaml"),
            serde_norway::to_string(&policy).unwrap(),
        )
        .unwrap();
        fs::write(
            project.join("sources/professional-licences.json"),
            BREG_SOURCE_DESCRIPTION,
        )
        .unwrap();
        fs::write(
            project.join("sources/response-register.json"),
            serde_json::to_string(&description).unwrap(),
        )
        .unwrap();
        (root, project)
    }

    #[test]
    fn check_reports_every_source_and_request_not_just_the_first() {
        let (_root, project) = write_two_source_project();

        let effective = check(&project, false, false).unwrap()["effective"].clone();

        let sources = effective["sources"].as_array().unwrap();
        assert_eq!(
            sources
                .iter()
                .map(|source| source["sourceId"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["professional-licences", "response-register"],
        );
        assert_eq!(
            sources
                .iter()
                .map(|source| source["requests"][0]["entity"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["scope-correction", "response-correction"],
        );
    }

    #[test]
    fn check_reports_the_authored_target_and_no_invented_clock() {
        let (_root, project) = write_two_source_project();

        let effective = check(&project, false, false).unwrap()["effective"].clone();
        let requests = [
            effective["sources"][0]["requests"][0].clone(),
            effective["sources"][1]["requests"][0].clone(),
        ];

        // Neither request declares a clock, so neither reports one. The old
        // report named a `first_observed_elapsed` clock that exists nowhere in
        // the model.
        for request in &requests {
            assert_eq!(request["clock"], Value::Null);
            assert!(request["target"].get("worker").is_none());
        }
        assert_eq!(requests[0]["target"]["id"], "first-review-response");
        assert_eq!(requests[0]["target"]["elapsed"], "PT48H");
        assert_eq!(requests[1]["target"]["id"], "response-window");
        assert_eq!(requests[1]["target"]["elapsed"], "PT72H");
    }

    #[test]
    fn test_accepts_a_fixture_naming_a_source_other_than_the_first() {
        let (_root, project) = write_two_source_project();
        fs::create_dir_all(project.join("fixtures")).unwrap();
        fs::write(
            project.join("fixtures/response.yaml"),
            "apiVersion: registry.registrystack.org/casework-fixture/v1alpha1\n\
             kind: CaseworkFixture\n\
             name: response-window\n\
             source: {id: response-register, requestEntity: response-correction}\n\
             expect: {queue: corrections, applicationMode: manual, targetElapsed: PT72H}\n",
        )
        .unwrap();

        test(&project).expect("a fixture naming the second source must resolve to that source");
    }
}
