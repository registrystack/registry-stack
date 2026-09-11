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
use registry_platform_config::{SecretError, SecretProvider, SecretReference, SecretResolver};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

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
    # Every secret:file reference resolves under this root. A secret file must
    # be owner-only text with no NUL byte, such as `openssl rand -hex 32`
    # (GitHub issue #976), and carry mode 0400 or 0600.
    root: secrets
database:
  runtimeUrlRef: secret:env/CASEWORK_DATABASE_URL
  migrationUrlRef: secret:env/CASEWORK_MIGRATION_DATABASE_URL
authentication:
  oidc:
    issuer: https://identity.example.test/realms/registry
    audience: urn:example:casework
    scopeClaim: registry_scopes
    # Signing keys come from issuer discovery by default. Declare the static
    # alternative instead when the runtime cannot reach the issuer's discovery
    # document, when the deployment is air-gapped, or when a test issuer's keys
    # are pinned by hand. It does no rotation of its own: rolling a key means
    # replacing the referenced document and restarting Casework.
    # jwksSource:
    #   kind: static
    #   documentRef: secret:file/jwks.json
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

/// The local clients `caseworkctl init` writes beside the standalone project.
pub(super) const STANDALONE_DEV_CLIENTS: &str = r#"# Local callers for `caseworkctl dev`. Registry Mint, the local token issuer
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
/// and `mint` issues their tokens from the operator's own issuer.
pub(super) const PROFESSIONAL_REVIEW_DEV_CLIENTS: &str = r#"# Local callers for this Casework project. Each client binds one access
# profile `casework.yaml` declares and carries the claims that profile reads:
# `registry_principal` is this project's `principalClaim`, and
# `registry_actor_kind: human` is the claim Casework requires of a person.
#
# This project binds a BReg source, so `caseworkctl dev` does not serve it: a
# source binding needs a running source system and its own reader credential.
# Point these clients at the deployed runtime's own token issuer.
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
            "Run caseworkctl source add with the authored BReg project and --source-id professional-register."),
        "standalone-decision" => (STANDALONE_YAML, "standalone-decision.yaml", STANDALONE_FIXTURE, STANDALONE_DEV_CLIENTS,
            "Run caseworkctl dev to start a local Casework runtime, its database and its token issuer, with the directory in dev-clients.yaml already seeded."),
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
    fs::write(staging.path().join("dev-clients.yaml"), dev_clients)?;
    let staging_path = staging.keep();
    fs::rename(&staging_path, project)
        .context("publishing Casework project without replacement")?;
    Ok(json!({
        "ok": true,
        "command": "init",
        "template": template,
        "project": project,
        "created": ["casework.yaml", "operator.example.yaml", "dev-clients.yaml", format!("fixtures/{fixture_name}"), "sources/"],
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
pub(super) fn load_and_check_policy(project: &Path) -> Result<CaseworkProject> {
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
        "audit.secretRef".to_owned(),
        config.audit.secret_ref.as_str(),
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
    let root = &config.secret_providers.file.root;
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
            root.display()
        );
    }
    Ok(checks)
}

pub(super) fn doctor(project: &Path, operator: Option<&Path>) -> Result<Value> {
    let (project, operator, config) = load_runtime(project, operator)?;
    check_source_descriptions(&project)?;
    let resolver = secret_resolver(&config).context("configuring Casework secret providers")?;
    let secret_files = secret_file_checks(&config, &resolver)?;
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
    let mut source_checks = Vec::with_capacity(policy.sources.len());
    for source in &policy.sources {
        let binding = config
            .sources
            .get(&source.id)
            .with_context(|| format!("operator source binding {} is missing", source.id))?;
        let adapter = binding
            .build_adapter(source, &project, &resolver)
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
        "project": project,
        "operator": operator,
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

pub(super) fn retention_erase(
    project: &Path,
    operator: Option<&Path>,
    source_id: String,
    request_kind: String,
    request_id: String,
    apply: bool,
) -> Result<Value> {
    let (project, operator, config) = load_runtime(project, operator)?;
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
    Ok(source_retention_output(&project, &operator, report))
}

fn source_retention_output(
    project: &Path,
    operator: &Path,
    report: SourceRetentionReport,
) -> Value {
    json!({
        "ok": true,
        "command": "retention erase",
        "project": project,
        "operator": operator,
        "report": report,
    })
}

pub(super) fn attempt_settle(
    project: &Path,
    operator: Option<&Path>,
    settlement: AttemptSettlement,
    apply: bool,
) -> Result<Value> {
    let (project, operator, config) = load_runtime(project, operator)?;
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
    Ok(attempt_settlement_output(&project, &operator, report))
}

fn attempt_settlement_output(
    project: &Path,
    operator: &Path,
    report: AttemptSettlementReport,
) -> Value {
    json!({
        "ok": true,
        "command": "attempt settle",
        "project": project,
        "operator": operator,
        "report": report,
    })
}

pub(super) fn operator_path(project: &Path, requested: Option<&Path>) -> PathBuf {
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
            Path::new("/casework/operator.yaml"),
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
            Path::new("/casework/operator.yaml"),
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
        assert_eq!(output["operator"], "/casework/operator.yaml");
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
                vec!["administrator", "supervisor", "staff"],
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
        let operator = project.join("operator.yaml");
        fs::write(
            &operator,
            OPERATOR_YAML
                .split("\nsources:")
                .next()
                .unwrap()
                .replace("listen: 127.0.0.1:8091", "listen: 127.0.0.1:8092"),
        )
        .unwrap();
        let config = RuntimeConfig::load(&operator).unwrap();
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
                "audit.secretRef"
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
        assert!(refusal.contains("audit.secretRef"), "{refusal}");
        assert!(refusal.contains("0400 or 0600"), "{refusal}");
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
        let operator = project.join("operator.yaml");
        let document = OPERATOR_YAML
            .split("\nsources:")
            .next()
            .unwrap()
            .replace("listen: 127.0.0.1:8091", "listen: 127.0.0.1:8092")
            .replace(
                "secret:env/CASEWORK_MIGRATION_DATABASE_URL",
                "secret:file/migration-database-url",
            )
            .replace(
                "secret:file/casework-audit-key",
                "secret:env/CASEWORK_AUDIT_KEY",
            );
        fs::write(&operator, document).unwrap();
        let config = RuntimeConfig::load(&operator).unwrap();
        let resolver = secret_resolver(&config).unwrap();
        let migration = SecretReference::parse(&config.database.migration_url_ref).unwrap();

        assert_eq!(
            resolver.resolve_reference(&migration).unwrap_err(),
            SecretError::Unavailable
        );
        let refusal = format!("{:#}", doctor(&project, Some(&operator)).unwrap_err());
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
        let operator = project.join("operator.yaml");
        let valid = OPERATOR_YAML
            .split("\nsources:")
            .next()
            .unwrap()
            .replace("listen: 127.0.0.1:8091", "listen: 127.0.0.1:8092");

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
            fs::write(&operator, valid.replace(authored, malformed)).unwrap();

            let refusal = format!("{:#}", doctor(&project, Some(&operator)).unwrap_err());
            assert!(refusal.contains(setting), "{refusal}");
            assert!(
                refusal.contains("secret:env/NAME or secret:file/name"),
                "{refusal}"
            );
            assert!(refusal.contains("secret reference is invalid"), "{refusal}");
        }
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
}
