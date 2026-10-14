// SPDX-License-Identifier: Apache-2.0
use anyhow::{bail, Context, Result};
use registry_casework::{
    open_audit, package_limits, secret_resolver, PostgresStore, RuntimeConfig, PACKAGE_COMMAND,
};
use registry_casework_core::{CaseworkProject, ConfigLoadError, ReviewContextPolicy};
use registry_platform_config::{plan_package, write_package, SecretResolver};
use registry_platform_yaml::{Decoded, Report};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
pub(crate) const LOCAL_PACKAGE_DIRECTORY: &str = ".casework/package";
pub(super) const STANDALONE_YAML: &str = r#"apiVersion: id.registrystack.org/formats/casework/project/v1alpha1
kind: CaseworkProject
project:
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
reviewPolicies:
  - id: decision
    version: "1"
    purpose: answer
    context: {mode: submitted}
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
trustedProducers:
  - id: requester
    profile: requester
    issuer: http://127.0.0.1:8093
    subject: b75315b2-5854-70f3-8867-511dd771a6da
    sourceNamespaces: [standalone]
    reviewPolicies: [decision]
    recoveryDays: 30
"#;

const STANDALONE_FIXTURE: &str = r#"apiVersion: id.registrystack.org/formats/casework/fixture/v1alpha1
kind: CaseworkFixture
id: standalone-decision-offline
review:
  policy: decision
  display:
    summary: Confirm the prepared synthetic batch
    reference: synthetic-batch-0042
expect:
  queue: decisions
  outcomes: [confirmed, rejected]
"#;

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
apiVersion: id.registrystack.org/formats/casework/dev-clients/v1alpha1
kind: CaseworkDevClients
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

pub(super) fn init(project: &Path, template: &str) -> Result<Value> {
    if template != "standalone-decision" {
        bail!("unknown template; available templates: standalone-decision");
    }
    if project.exists() {
        bail!("destination already exists; init never overwrites a project");
    }
    let parent = project
        .parent()
        .context("project destination has no parent")?;
    fs::create_dir_all(parent)?;
    let stage = tempfile::tempdir_in(parent)?;
    fs::create_dir_all(stage.path().join("fixtures"))?;
    // Init owns this fresh staging directory. Dev later stores credentials
    // under .casework and requires its parent to be owner-only from creation.
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(stage.path().join(".casework"))?;
    }
    fs::create_dir_all(stage.path().join(".casework/schemas"))?;
    fs::create_dir_all(stage.path().join(".vscode"))?;
    fs::write(stage.path().join("casework.yaml"), STANDALONE_YAML)?;
    fs::write(
        stage.path().join("fixtures/standalone-decision.yaml"),
        STANDALONE_FIXTURE,
    )?;
    fs::write(
        stage.path().join("dev-clients.yaml"),
        STANDALONE_DEV_CLIENTS,
    )?;
    let absolute = std::path::absolute(project)?;
    let runtime = json!({"apiVersion":"id.registrystack.org/formats/casework/runtime/v1alpha1","kind":"CaseworkRuntimeConfig",
        "identity":{"databaseId":"casework-example"},"package":{"root":absolute.join(LOCAL_PACKAGE_DIRECTORY)},
        "listener":{"bind":"127.0.0.1:8100","tlsTermination":"development-loopback","networkExposure":"private-address"},
        "secretProviders":{"file":{"root":absolute.join("secrets")}},
        "database":{"runtimeUrlRef":"secret:file/runtime-database-url","migrationUrlRef":"secret:file/migration-database-url"},
        "authentication":{"oidc":{"issuer":"https://identity.example.test","audience":"urn:example:casework","allowedClients":"unrestricted","scopeClaim":"scope","humanIdentity":{"claim":"registry_actor_kind","value":"human"}}},
        "audit":{"path":absolute.join("state/audit.ndjson"),"hashKeyRef":"secret:file/casework-audit-key"},"contextProviders":{}});
    fs::write(
        stage.path().join("runtime.example.yaml"),
        serde_norway::to_string(&runtime)?,
    )?;
    for (name, content) in [
        (
            "project.schema.json",
            include_str!("../../../products/casework/generated/project/project.schema.json"),
        ),
        (
            "runtime.schema.json",
            include_str!("../../../products/casework/generated/runtime/runtime.schema.json"),
        ),
        (
            "dev-clients.schema.json",
            include_str!(
                "../../../products/casework/generated/dev-clients/dev-clients.schema.json"
            ),
        ),
    ] {
        fs::write(stage.path().join(".casework/schemas").join(name), content)?;
    }
    fs::write(
        stage.path().join(".vscode/settings.json"),
        serde_json::to_vec_pretty(
            &json!({"yaml.schemas":{"./.casework/schemas/project.schema.json":"casework.yaml","./.casework/schemas/runtime.schema.json":"runtime.example.yaml","./.casework/schemas/dev-clients.schema.json":"dev-clients.yaml"}}),
        )?,
    )?;
    load_and_check_policy(stage.path())?;
    fs::rename(stage.path(), project)?;
    Ok(
        json!({"ok":true,"command":"init","created":project,"template":template,"next":"Run caseworkctl check, test and types, then caseworkctl dev start."}),
    )
}

pub(crate) fn read_project(project: &Path) -> Result<Decoded<CaseworkProject>> {
    let path = project.join("casework.yaml");
    let bytes = fs::read(&path).map_err(ConfigLoadError::Read)?;
    Ok(CaseworkProject::read(&path.display().to_string(), &bytes)
        .map_err(ConfigLoadError::Refused)?)
}
pub(crate) fn load_and_check_policy(project: &Path) -> Result<CaseworkProject> {
    Ok(CaseworkProject::load(project.join("casework.yaml"))?)
}
pub(super) fn check(project: &Path, _production: bool, _deny_warnings: bool) -> Result<Value> {
    let policy = load_and_check_policy(project)?;
    let policy_bytes = read_package_input(&project.join("casework.yaml"))?;
    let mut files_checked =
        registry_casework_core::CaseworkProject::schema_references("casework.yaml", &policy_bytes)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
    let mut diagnostics = Report::default();
    for (relative, is_state) in [
        ("dev-clients.yaml", false),
        (".casework/dev/state.json", true),
    ] {
        let path = project.join(relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() || metadata.len() > 4 * 1024 * 1024 {
            bail!(
                "{} must be a regular file of at most four MiB",
                path.display()
            );
        }
        let bytes = fs::read(&path)?;
        let shown = path.display().to_string();
        if is_state {
            diagnostics.extend(crate::dev::check_state(&shown, &bytes));
        } else {
            match crate::dev::config::read_against(&shown, &bytes, &policy) {
                Ok(decoded) => diagnostics.extend(decoded.document.warnings()),
                Err(refused) => diagnostics.extend(refused),
            }
        }
        files_checked.insert(relative.to_owned());
    }
    if diagnostics.has_errors() {
        return Err(diagnostics.into());
    }
    let bindings = policy
        .review_policies
        .iter()
        .map(|p| p.compile(&policy).map(|c| c.identity))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for provider in &policy.context_providers {
        if let Some(description) = &provider.description {
            files_checked.insert(description.clone());
            let bytes = read_package_input(&project_input_path(project, description)?)?;
            let export: registry_casework_breg::BregContextExport =
                serde_json::from_value(registry_breg_client_value(&bytes)?)?;
            export.check()?;
            if export.source_namespace != provider.source_namespace {
                bail!("provider export namespace differs from its compiled binding");
            }
            for review in &policy.review_policies {
                if let ReviewContextPolicy::CurrentSource {
                    provider: id,
                    contract,
                } = &review.context
                {
                    if id == &provider.id && contract != &export.contract {
                        bail!("provider export context contract differs from the compiled policy");
                    }
                }
            }
        }
    }
    Ok(
        json!({"ok":true,"command":"check","status":"complete","project":project,"policyBindings":bindings,"filesChecked":files_checked.len()+1,"diagnostics":diagnostics.diagnostics(),"networkAccess":false,"databaseAccess":false}),
    )
}
fn registry_breg_client_value(bytes: &[u8]) -> Result<Value> {
    let document = registry_platform_yaml::Reader::new("context-provider.json")
        .scan(bytes)?
        .context("context export is empty")?;
    Ok(document.to_json_value())
}
pub(super) fn explain(project: &Path) -> Result<Value> {
    check(project, false, false)?;
    let policy = load_and_check_policy(project)?;
    let reviews = policy.review_policies.iter().map(|review| {
        let compiled = review.compile(&policy)?;
        let custody = match review.context {
            ReviewContextPolicy::Submitted => "admitted bounded snapshot",
            ReviewContextPolicy::CurrentSource { .. } => "fresh human caller read; source values are ephemeral",
        };
        Ok(json!({
            "binding": compiled.identity,
            "purpose": review.purpose,
            "context": review.context,
            "contextCustody": custody,
            "displaySchema": review.display_schema,
            "resultSchema": review.result_schema,
            "stages": review.stages,
            "outcomes": review.outcomes,
            "routing": review.routing,
            "routingFields": review.routing_fields(),
            "clocks": review.clocks,
            "dependencies": compiled.dependencies,
            "retention": review.retention,
            "recovery": ["request idempotency receipt", "revision-fenced decision receipt", "authenticated result fetch and resumable feed"],
            "refusals": ["untrusted producer", "policy binding mismatch", "concealed source", "changed subject or contract", "stale task revision", "ineligible reviewer"],
        }))
    }).collect::<std::result::Result<Vec<Value>,registry_casework_core::ReviewPolicyError>>()?;
    Ok(
        json!({"ok":true,"command":"explain","project":policy.project,"reviewPolicies":reviews,"contextProviders":policy.context_providers,"staffing":{"next":"due ordered eligible visible tasks","holdings":"claimed or assigned tasks under current visibility","caseload":"atomic preview and revision-fenced apply","routing":"once per task or stage from compiled minimized fields","clockRecompute":"pinned policy closure"},"authority":"producer, human reviewer and downstream executor authenticate independently"}),
    )
}
pub(super) fn test(project: &Path) -> Result<Value> {
    check(project, false, false)?;
    let policy = load_and_check_policy(project)?;
    let mut checked = Vec::new();
    let fixtures = project.join("fixtures");
    if fixtures.is_dir() {
        let mut paths = fs::read_dir(fixtures)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.sort();
        for path in paths {
            if !path.is_file() {
                continue;
            }
            let bytes = read_package_input(&path)?;
            let fixture = registry_platform_yaml::Reader::new(path.display().to_string())
                .scan(&bytes)?
                .context("fixture is empty")?
                .to_json_value();
            if fixture["apiVersion"] != "id.registrystack.org/formats/casework/fixture/v1alpha1"
                || fixture["kind"] != "CaseworkFixture"
            {
                bail!("fixture has the wrong envelope");
            }
            let review = &fixture["review"];
            let id = review["policy"]
                .as_str()
                .context("fixture review.policy is required")?;
            let p = policy
                .review_policies
                .iter()
                .find(|p| p.id == id)
                .context("fixture policy is not declared")?;
            p.validate_display(&review["display"])?;
            if let Some(queue) = fixture["expect"]["queue"].as_str() {
                if p.stages.first().is_none_or(|stage| stage.queue != queue) {
                    bail!("fixture expected queue differs from policy");
                }
            }
            if let Some(outcomes) = fixture["expect"]["outcomes"].as_array() {
                let actual = p.outcomes.iter().map(|o| o.id.as_str()).collect::<Vec<_>>();
                if outcomes
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    != actual
                {
                    bail!("fixture expected outcomes differ from policy");
                }
            }
            checked.push(path);
        }
    }
    Ok(
        json!({"ok":true,"command":"test","fixtures":checked,"proofBoundary":"offline-synthetic","productionClosure":false,"networkAccess":false,"databaseAccess":false}),
    )
}

pub(crate) fn project_input_path(project: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        bail!("input must be a normalized relative project path");
    }
    let root = fs::canonicalize(project)?;
    let candidate = fs::canonicalize(root.join(path))?;
    if !candidate.starts_with(&root) {
        bail!("input leaves the project");
    }
    Ok(candidate)
}
pub(crate) fn read_package_input(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() || meta.len() > 1024 * 1024 {
        bail!("input must be a regular file of at most one MiB");
    }
    Ok(fs::read(path)?)
}
fn package_contents(project: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    check(project, true, true)?;
    let policy = load_and_check_policy(project)?;
    let policy_bytes = read_package_input(&project.join("casework.yaml"))?;
    registry_casework::package_inputs(&policy, &policy_bytes)?
        .into_iter()
        .map(|path| {
            let bytes = read_package_input(&project_input_path(project, &path)?)?;
            Ok((path, bytes))
        })
        .collect()
}
pub(super) fn package(project: &Path, output: &Path, revision: Option<&str>) -> Result<Value> {
    let inputs = package_contents(project)?;
    let written = write_package(
        output,
        &inputs,
        revision,
        &package_limits(),
        PACKAGE_COMMAND,
    )?;
    Ok(
        json!({"ok":true,"command":"package","output":output,"packageDigest":written.digest(),"revision":written.revision(),"secretsIncluded":false}),
    )
}
pub(super) fn package_dry_run(project: &Path, revision: Option<&str>) -> Result<Value> {
    let inputs = package_contents(project)?;
    let digest = plan_package(
        project,
        &inputs,
        revision,
        &package_limits(),
        PACKAGE_COMMAND,
    )?;
    Ok(
        json!({"ok":true,"command":"package","dryRun":true,"packageDigest":digest,"files":inputs.keys().collect::<Vec<_>>()}),
    )
}
struct ActivationInputs {
    config: RuntimeConfig,
    runtime_config: PathBuf,
    package: registry_casework::LoadedCaseworkPackage,
    resolver: SecretResolver,
    providers: Vec<std::sync::Arc<dyn registry_casework_core::ReviewContextProvider>>,
}

impl ActivationInputs {
    fn load(runtime_config: &Path) -> Result<Self> {
        let config = load_runtime_config(runtime_config)?;
        let runtime_config =
            fs::canonicalize(runtime_config).context("resolving Casework runtime configuration")?;
        let package = config
            .load_package()
            .context("verifying the configured Casework package")?;
        let resolver = secret_resolver(&config).context("configuring Casework secret providers")?;
        let providers = registry_casework::build_context_providers(&config, &package, &resolver)
            .context("building the Casework context providers")?;
        Ok(Self {
            config,
            runtime_config,
            package,
            resolver,
            providers,
        })
    }

    fn provider_refs(&self) -> Vec<&dyn registry_casework_core::ReviewContextProvider> {
        self.providers
            .iter()
            .map(|adapter| adapter.as_ref())
            .collect()
    }

    fn candidate<'a>(
        &'a self,
        providers: &'a [&'a dyn registry_casework_core::ReviewContextProvider],
    ) -> registry_casework::ActivationCandidate<'a> {
        registry_casework::ActivationCandidate {
            database_id: self.config.database_id(),
            package_digest: self.package.digest(),
            project: self.package.project(),
            providers,
        }
    }
}

/// Merge a serialized activation value into a report that already names
/// the command and the runtime configuration.
fn activation_report(mut report: Value, fields: impl serde::Serialize) -> Result<Value> {
    let Value::Object(fields) =
        serde_json::to_value(fields).context("rendering the Casework activation report")?
    else {
        bail!("the Casework activation report is not an object");
    };
    report
        .as_object_mut()
        .expect("activation reports are objects")
        .extend(fields);
    Ok(report)
}

fn single_role_statement(role_mode: Option<registry_casework::RoleMode>) -> Value {
    if role_mode == Some(registry_casework::RoleMode::Single) {
        Value::from(registry_casework::SINGLE_ROLE_STATEMENT)
    } else {
        Value::Null
    }
}

pub(super) fn plan(runtime_config: &Path) -> Result<Value> {
    let inputs = ActivationInputs::load(runtime_config)?;
    let providers = inputs.provider_refs();
    let candidate = inputs.candidate(&providers);
    let store = PostgresStore::connect_runtime(&inputs.config.database, &inputs.resolver)
        .context("the Casework runtime database configuration is invalid")?;
    let plan = async_runtime()?
        .block_on(store.plan_activation(&candidate))
        .context("planning the Casework package activation")?;
    let refused = plan
        .refusals
        .iter()
        .any(|refusal| refusal.code != "casework.activation.already-active");
    let mut report = json!({
        "ok": !refused,
        "command": "plan",
        "runtimeConfig": inputs.runtime_config,
    });
    if refused {
        report["diagnostics"] = serde_json::to_value(&plan.refusals)?;
    }
    activation_report(report, plan)
}

pub(super) fn apply(
    runtime_config: &Path,
    operator_reference: Option<String>,
    backup_references: Vec<String>,
) -> Result<Value> {
    let inputs = ActivationInputs::load(runtime_config)?;
    let providers = inputs.provider_refs();
    let candidate = inputs.candidate(&providers);
    let runtime = async_runtime()?;
    // The role the runtime credential connects as decides the role mode;
    // only apply resolves the migration credential.
    let runtime_user = {
        let store = PostgresStore::connect_runtime(&inputs.config.database, &inputs.resolver)
            .context("the Casework runtime database configuration is invalid")?;
        runtime
            .block_on(store.current_user())
            .context("reading the Casework runtime database role")?
    };
    let store = PostgresStore::connect_migration(&inputs.config.database, &inputs.resolver)
        .context("the Casework migration database configuration is invalid")?;
    let store = with_operator_audit(store, &inputs.config, &inputs.resolver, &runtime)?;
    let applied = runtime
        .block_on(store.apply_activation(
            &runtime_user,
            &candidate,
            &registry_casework::ApplyRequest {
                operator_reference,
                backup_references,
            },
        ))
        .context("applying the Casework package")?;
    let role_mode = applied.activation.role_mode;
    let report = activation_report(
        json!({
            "ok": true,
            "command": "apply",
            "runtimeConfig": inputs.runtime_config,
            "schemaVersionsApplied": applied.schema_versions_applied,
            "effects": applied.effects,
            "singleRoleStatement": single_role_statement(Some(role_mode)),
        }),
        applied.activation,
    )?;
    Ok(report)
}

pub(super) fn status(runtime_config: &Path) -> Result<Value> {
    let config = load_runtime_config(runtime_config)?;
    let runtime_config =
        fs::canonicalize(runtime_config).context("resolving Casework runtime configuration")?;
    let resolver = secret_resolver(&config).context("configuring Casework secret providers")?;
    let store = PostgresStore::connect_runtime(&config.database, &resolver)
        .context("the Casework runtime database configuration is invalid")?;
    let status = async_runtime()?
        .block_on(store.activation_status())
        .context("reading the Casework activation ledger")?;
    let statement = single_role_statement(status.role_mode);
    activation_report(
        json!({
            "ok": true,
            "command": "status",
            "runtimeConfig": runtime_config,
            "singleRoleStatement": statement,
        }),
        status,
    )
}

fn with_operator_audit(
    store: PostgresStore,
    config: &RuntimeConfig,
    resolver: &SecretResolver,
    runtime: &tokio::runtime::Runtime,
) -> Result<PostgresStore> {
    let audit = runtime
        .block_on(open_audit(config, resolver, Some("caseworkctl")))
        .context("opening the Casework operator audit destination")?;
    Ok(store.with_audit(audit))
}

fn async_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the Casework operator runtime")
}

fn load_runtime_config(path: &Path) -> Result<RuntimeConfig> {
    Ok(RuntimeConfig::load(path)?)
}
pub(super) fn check_runtime_config(
    project: &Path,
    path: &Path,
    environment: bool,
    checked: Result<Value>,
) -> Result<Value> {
    let policy = load_and_check_policy(project).ok();
    let absolute = std::path::absolute(path)?;
    let report = registry_casework::check_runtime(&absolute, policy.as_ref(), environment);
    let report = Report::new(report.diagnostics);
    if report.has_errors() {
        return Err(report.into());
    }
    let mut checked = checked?;
    checked["runtimeConfig"] = json!(path);
    Ok(checked)
}
pub(super) fn doctor(path: &Path) -> Result<Value> {
    let inputs = ActivationInputs::load(path)?;
    let refs = inputs.provider_refs();
    let candidate = inputs.candidate(&refs);
    let store = PostgresStore::connect_runtime(&inputs.config.database, &inputs.resolver)?;
    let runtime = async_runtime()?;
    runtime.block_on(store.current_user())?;
    let mut plan = runtime.block_on(store.plan_activation(&candidate))?;
    // Already active is an apply refusal, not a health failure. Keep this
    // distinction local to doctor; plan/apply retain their activation rules.
    plan.refusals
        .retain(|refusal| refusal.code != "casework.activation.already-active");
    inputs.config.audit.destination()?.check_writable()?;
    Ok(
        json!({"ok":plan.refusals.is_empty(),"command":"doctor","runtimeConfig":path,"packageDigest":inputs.package.digest(),"activation":plan,"checks":{"configuration":"ready","package":"ready","database":"ready","audit":"ready"}}),
    )
}
