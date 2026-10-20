// SPDX-License-Identifier: Apache-2.0
use anyhow::{bail, Context, Result};
use registry_casework::{
    open_audit, package_limits, secret_resolver, PostgresStore, RuntimeConfig, PACKAGE_COMMAND,
};
use registry_casework_core::{CaseworkProject, ConfigLoadError, ReviewContextPolicy};
use registry_platform_config::{plan_package, write_package, SecretResolver};
use registry_platform_yaml::{Decoded, Diagnostic, Report, Severity, Source};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::Read as _,
    path::{Path, PathBuf},
};
pub(crate) const LOCAL_PACKAGE_DIRECTORY: &str = ".casework/package";
const MAXIMUM_HOLIDAY_SET_FILES: usize = 1024;
pub(super) const STANDALONE_YAML: &str = r#"# yaml-language-server: $schema=.casework/schemas/project.schema.json
apiVersion: id.registrystack.org/formats/casework/project/v1alpha1
kind: CaseworkProject
project:
  id: standalone-decision
  version: "1"
accessProfiles:
  staff:
    principalClaim: sub
    requiredScopes: [casework:staff]
    role: staff
  supervisor:
    principalClaim: sub
    requiredScopes: [casework:supervisor]
    role: supervisor
  administrator:
    principalClaim: sub
    requiredScopes: [casework:admin]
    role: administrator
  requester:
    principalClaim: sub
    requiredScopes: [casework:request]
    role: requester
queues:
  decisions:
    label: Decisions awaiting review
reviewPolicies:
  decision:
    version: "1"
    purpose: answer
    context: {mode: submitted}
    stages:
      - id: answer
        queue: decisions
        decidingProfiles: [staff]
        requiredApprovals: 1
    retention:
      terminalRetentionDays: 90
      accountabilityRetentionDays: 365
    displaySchema:
      type: object
      additionalProperties: false
      required: [summary, reference]
      properties:
        summary: {type: string, maxLength: 160}
        reference: {type: string, maxLength: 120}
    outcomes:
      confirmed:
        label: Confirm
        settlement: answered
        reasonRequired: false
        publicReason: optional
      rejected:
        label: Return for correction
        settlement: answered
        reasonRequired: true
        publicReason: required
trustedProducers:
  requester:
    profile: requester
    issuer: http://127.0.0.1:8093
    subject: b75315b2-5854-70f3-8867-511dd771a6da
    sourceNamespaces: [standalone]
    reviewPolicies: [decision]
    retention: {receiptRetentionDays: 30}
"#;

const STANDALONE_FIXTURE: &str = r#"# yaml-language-server: $schema=../.casework/schemas/fixture.schema.json
apiVersion: id.registrystack.org/formats/casework/fixture/v1alpha1
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

pub(super) const STANDALONE_DEV_CLIENTS: &str = r#"# yaml-language-server: $schema=.casework/schemas/dev-clients.schema.json
# Local callers for `caseworkctl dev`. The pinned local token issuer
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
    if !matches!(template, "standalone-decision" | "canonical-review") {
        bail!("unknown template; available templates: standalone-decision, canonical-review");
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
    let canonical_review = template == "canonical-review";
    fs::write(
        stage.path().join("casework.yaml"),
        if canonical_review {
            include_str!("../../../products/casework/examples/canonical-review/casework.yaml")
        } else {
            STANDALONE_YAML
        },
    )?;
    if canonical_review {
        fs::create_dir_all(stage.path().join("schemas"))?;
        fs::write(
            stage.path().join("schemas/correct-address.schema.json"),
            include_bytes!(
                "../../../products/casework/examples/canonical-review/schemas/correct-address.schema.json"
            ),
        )?;
        fs::write(
            stage.path().join("README.md"),
            include_bytes!("../../../products/casework/examples/canonical-review/README.md"),
        )?;
    }
    fs::write(
        stage.path().join("fixtures/standalone-decision.yaml"),
        STANDALONE_FIXTURE,
    )?;
    fs::write(
        stage.path().join("dev-clients.yaml"),
        if canonical_review {
            include_str!("../../../products/casework/examples/canonical-review/dev-clients.yaml")
        } else {
            STANDALONE_DEV_CLIENTS
        },
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
        format!(
            "# yaml-language-server: $schema=.casework/schemas/runtime.schema.json\n{}",
            serde_norway::to_string(&runtime)?
        ),
    )?;
    if canonical_review {
        fs::write(
            stage.path().join("runtime.example.yaml"),
            format!(
                "# yaml-language-server: $schema=.casework/schemas/runtime.schema.json\n{}",
                include_str!(
                    "../../../products/casework/examples/canonical-review/runtime.example.yaml"
                )
            ),
        )?;
    }
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
        (
            "fixture.schema.json",
            include_str!("../../../products/casework/generated/fixture/fixture.schema.json"),
        ),
    ] {
        fs::write(stage.path().join(".casework/schemas").join(name), content)?;
    }
    fs::write(
        stage.path().join(".vscode/settings.json"),
        serde_json::to_vec_pretty(
            &json!({"yaml.schemas":{"./.casework/schemas/project.schema.json":"casework.yaml","./.casework/schemas/runtime.schema.json":"runtime.example.yaml","./.casework/schemas/dev-clients.schema.json":"dev-clients.yaml","./.casework/schemas/fixture.schema.json":"fixtures/*.yaml"}}),
        )?,
    )?;
    load_and_check_policy(stage.path())?;
    fs::rename(stage.path(), project)?;
    Ok(
        json!({"ok":true,"command":"init","created":project,"template":template,"next":if canonical_review { "Run caseworkctl check, then pair the BReg provider and configure source transport before caseworkctl dev start." } else { "Run caseworkctl check, test and types, then caseworkctl dev start." }}),
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
pub(super) fn check(project: &Path, _production: bool, deny_warnings: bool) -> Result<Value> {
    let decoded = read_project(project)?;
    let policy = decoded.value;
    let mut diagnostics = decoded.document.warnings();
    check_served_capabilities(project, &policy)?;
    let policy_bytes = read_package_input(&project.join("casework.yaml"))?;
    let mut files_checked =
        registry_casework_core::CaseworkProject::schema_references("casework.yaml", &policy_bytes)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
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
    check_holiday_sets(project, &mut files_checked, &mut diagnostics)?;
    if diagnostics.has_errors() || (deny_warnings && diagnostics.warning_count() > 0) {
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

/// Refuses a project that needs a review-context capability its source does
/// not serve. Every context provider the runtime builds is a BReg provider,
/// so the BReg adapter decides which capabilities are served.
fn check_served_capabilities(project: &Path, policy: &CaseworkProject) -> Result<()> {
    let findings: Vec<_> = policy
        .context_providers
        .iter()
        .flat_map(|provider| registry_casework_breg::unserved_capabilities(policy, provider))
        .collect();
    if findings.is_empty() {
        return Ok(());
    }
    let document = read_project(project)?.document;
    Err(registry_casework_core::findings_report(&document, &findings).into())
}

fn check_holiday_sets(
    project: &Path,
    files_checked: &mut std::collections::BTreeSet<String>,
    diagnostics: &mut Report,
) -> Result<()> {
    let directory = project.join("holiday-sets");
    let directory_shown = directory.display().to_string();
    let metadata = match fs::metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && fs::symlink_metadata(&directory).is_err() =>
        {
            return Ok(());
        }
        Err(_) => {
            diagnostics.push(unreadable_holiday_input(&directory_shown));
            return Ok(());
        }
    };
    if !metadata.file_type().is_dir() {
        diagnostics.push(holiday_file_diagnostic(
            Severity::Error,
            "casework.project.not-a-directory",
            &directory_shown,
            "holiday-sets/ is not a directory, so caseworkctl cannot read its authored holiday sets",
            "Replace the file with a directory holding the holiday-set YAML files.",
        ));
        return Ok(());
    }
    let mut paths = Vec::new();
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(_) => {
            diagnostics.push(unreadable_holiday_input(&directory_shown));
            return Ok(());
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                diagnostics.push(unreadable_holiday_input(&directory_shown));
                return Ok(());
            }
        };
        let path = entry.path();
        let shown = path.display().to_string();
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                diagnostics.push(unreadable_holiday_input(&shown));
                continue;
            }
        };
        if metadata.is_dir() {
            diagnostics.push(holiday_file_diagnostic(
                Severity::Warning,
                "casework.project.unread-directory",
                &shown,
                "caseworkctl reads holiday-set files only directly under holiday-sets/, so nothing in this directory is read",
                "Move the holiday-set files up into holiday-sets/, or move this directory out of holiday-sets/.",
            ));
            continue;
        }
        if !is_yaml_path(&path) {
            continue;
        }
        paths.push((path, metadata));
        if paths.len() > MAXIMUM_HOLIDAY_SET_FILES {
            diagnostics.push(holiday_file_diagnostic(
                Severity::Error,
                "casework.project.too-many-files",
                &directory_shown,
                format!("holiday-sets/ holds more than the {MAXIMUM_HOLIDAY_SET_FILES} YAML files caseworkctl reads, so none of them was read"),
                format!("Remove YAML files from holiday-sets/ until no more than {MAXIMUM_HOLIDAY_SET_FILES} remain."),
            ));
            return Ok(());
        }
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0));
    for (path, metadata) in paths {
        let shown = path.display().to_string();
        if !metadata.file_type().is_file() {
            diagnostics.push(holiday_file_diagnostic(
                Severity::Error,
                "casework.project.not-a-regular-file",
                &shown,
                "this holiday-set path is not a regular file",
                "Replace the special file with a regular YAML file holding the holiday set.",
            ));
            continue;
        }
        let mut bytes = Vec::new();
        let read = fs::File::open(&path).and_then(|file| {
            file.take((registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
        });
        if read.is_err() {
            diagnostics.push(unreadable_holiday_input(&shown));
            continue;
        }
        match registry_casework_core::CaseworkHolidaySet::read(&shown, &bytes) {
            Ok(decoded) => diagnostics.extend(decoded.document.warnings()),
            Err(refused) => diagnostics.extend(refused),
        }
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_default();
        files_checked.insert(format!("holiday-sets/{name}"));
    }
    Ok(())
}

fn is_yaml_path(path: &Path) -> bool {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
}

fn unreadable_holiday_input(file: &str) -> Diagnostic {
    holiday_file_diagnostic(
        Severity::Error,
        "casework.project.unreadable-file",
        file,
        "caseworkctl cannot read this holiday-set path",
        "Make the path readable by the user running caseworkctl, or remove it.",
    )
}

fn holiday_file_diagnostic(
    severity: Severity,
    code: &str,
    file: &str,
    message: impl Into<String>,
    action: impl Into<String>,
) -> Diagnostic {
    let mut diagnostic = match severity {
        Severity::Error => Diagnostic::error(code, "", message, action),
        _ => Diagnostic::warning(code, "", message, action),
    };
    diagnostic.source = Some(Source {
        file: file.to_owned(),
        line: None,
        column: None,
    });
    diagnostic
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
pub(super) fn test(project: &Path, deny_warnings: bool) -> Result<Value> {
    use std::io::Read as _;
    let project_check = check(project, false, deny_warnings)?;
    let policy = load_and_check_policy(project)?;
    let mut checked = Vec::new();
    let mut diagnostics = Report::new(serde_json::from_value(
        project_check["diagnostics"].clone(),
    )?);
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
            // The shared reader owns the one-MiB boundary and positioned
            // format diagnostics, including empty and oversized fixtures.
            if !fs::symlink_metadata(&path)?.file_type().is_file() {
                bail!("fixture input must be a regular file");
            }
            let mut bytes = Vec::new();
            fs::File::open(&path)?
                .take((registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            match registry_casework_core::CaseworkFixture::read_against(
                &path.display().to_string(),
                &bytes,
                &policy,
            ) {
                Ok(decoded) => {
                    diagnostics.extend(decoded.document.warnings());
                    checked.push(path);
                }
                Err(refused) => diagnostics.extend(refused),
            }
        }
    }
    if diagnostics.has_errors() || (deny_warnings && diagnostics.warning_count() > 0) {
        return Err(diagnostics.into());
    }
    Ok(
        json!({"ok":true,"command":"test","fixtures":checked,"diagnostics":diagnostics.diagnostics(),"proofBoundary":"offline-synthetic","productionClosure":false,"networkAccess":false,"databaseAccess":false}),
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
    inputs.config.check_runtime_secrets(&inputs.resolver)?;
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
    let shortfalls = if plan.active.is_some() {
        runtime.block_on(store.review_staffing_shortfalls(inputs.package.project()))?
    } else {
        Vec::new()
    };
    let diagnostics = shortfalls
        .into_iter()
        .map(|queue| {
            Diagnostic::warning(
            "casework.staffing.insufficient-distinct-approvers",
            format!("queues.{queue}"),
            "The serving team has fewer available distinct reviewers than a review stage requires.",
            "Add eligible reviewers to the serving team or review the stage's requiredApprovals.",
        )
        })
        .collect::<Vec<_>>();

    Ok(
        json!({"ok":plan.refusals.is_empty(),"diagnostics":diagnostics,"command":"doctor","runtimeConfig":path,"packageDigest":inputs.package.digest(),"activation":plan,"checks":{"configuration":"ready","package":"ready","database":"ready","audit":"ready"}}),
    )
}

#[cfg(test)]
mod display_integrity_tests {
    use super::*;

    #[test]
    fn check_reports_duplicate_display_text_and_deny_warnings_refuses_it() {
        let root = crate::canonical_tempdir();
        let project = root.path().join("project");
        init(&project, "standalone-decision").unwrap();
        let path = project.join("casework.yaml");
        let authored = fs::read_to_string(&path).unwrap().replacen(
            "label: Return for correction",
            "label: confirm",
            1,
        );
        fs::write(&path, authored).unwrap();

        let report = check(&project, false, false).expect("warnings do not normally refuse check");
        let warning = report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["code"] == "casework.review-policy.duplicate-outcome-label")
            .expect("the product check reports the duplicate label");
        assert_eq!(
            warning["path"],
            "/reviewPolicies/decision/outcomes/rejected/label"
        );

        let error = check(&project, false, true).expect_err("--deny-warnings refuses the warning");
        let report = crate::configuration_report(&error).expect("a structured warning report");
        assert_eq!(report.error_count(), 0);
        assert_eq!(report.warning_count(), 1);
        assert_eq!(
            report.diagnostics()[0].code,
            "casework.review-policy.duplicate-outcome-label"
        );
    }
}

#[cfg(test)]
mod doctor_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const CANARY: &str = "DOCTOR_SECRET_VALUE_CANARY";

    fn setup() -> (tempfile::TempDir, PathBuf) {
        let root = crate::canonical_tempdir();
        let project = root.path().join("project");
        init(&project, "standalone-decision").unwrap();
        let package_root = root.path().join("package");
        package(&project, &package_root, None).unwrap();
        let secrets = root.path().join("secrets");
        fs::create_dir(&secrets).unwrap();
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in [
            (
                "runtime-url",
                "postgresql://casework@127.0.0.1:1/casework?sslmode=require&connect_timeout=1",
            ),
            ("audit-key", CANARY),
            ("completion-token", CANARY),
        ] {
            write_secret(&secrets.join(name), bytes.as_bytes(), 0o600);
        }
        let config = json!({
            "apiVersion":registry_casework::RUNTIME_CONFIG_API_VERSION,"kind":registry_casework::RUNTIME_CONFIG_KIND,
            "identity":{"databaseId":"doctor-preflight"},"package":{"root":package_root},
            "listener":{"bind":"127.0.0.1:8100","tlsTermination":"development-loopback","networkExposure":"private-address"},
            "secretProviders":{"file":{"root":secrets}},
            "database":{"runtimeUrlRef":"secret:file/runtime-url","migrationUrlRef":"secret:file/absent-migration-url"},
            "authentication":{"oidc":{"issuer":"https://identity.example.test","audience":"urn:example:casework","allowedClients":"unrestricted","scopeClaim":"scope","humanIdentity":{"claim":"registry_actor_kind","value":"human"}}},
            "audit":{"path":root.path().join("audit.ndjson"),"hashKeyRef":"secret:file/audit-key"},
            "reviewCompletionDestinations":{"receiver":{"url":"https://completion.example.test/reviews","bearerTokenRef":"secret:file/completion-token"}}
        });
        let runtime = root.path().join("runtime.yaml");
        fs::write(&runtime, serde_norway::to_string(&config).unwrap()).unwrap();
        (root, runtime)
    }

    fn write_secret(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn doctor_refuses_startup_only_secrets_before_connecting_to_the_database() {
        for (name, field) in [
            ("audit-key", "audit.hashKeyRef"),
            (
                "completion-token",
                "reviewCompletionDestinations.receiver.bearerTokenRef",
            ),
        ] {
            let (root, runtime) = setup();
            fs::remove_file(root.path().join("secrets").join(name)).unwrap();
            let error = doctor(&runtime).unwrap_err();
            let shown = format!("{error:#}");
            assert!(shown.contains(field), "{shown}");
            assert!(!shown.contains("database connection"), "{shown}");
            assert!(!shown.contains(CANARY), "{shown}");
            for format in ["human", "json"] {
                let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
                let exit = crate::main_entry_from(
                    [
                        "caseworkctl".into(),
                        "--format".into(),
                        format.into(),
                        "doctor".into(),
                        "--runtime-config".into(),
                        runtime.as_os_str().to_owned(),
                    ],
                    &mut stdout,
                    &mut stderr,
                );
                assert_eq!(
                    exit,
                    std::process::ExitCode::from(crate::DOMAIN_REFUSAL_EXIT)
                );
                let shown = format!(
                    "{}{}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
                assert!(shown.contains(field), "{shown}");
                assert!(!shown.contains(CANARY), "{shown}");
                if format == "json" {
                    let report: Value = serde_json::from_slice(&stdout).unwrap();
                    assert_eq!(
                        report["diagnostics"][0]["code"],
                        "casework.runtime.secret-unavailable"
                    );
                    assert!(stderr.is_empty());
                } else {
                    assert!(stdout.is_empty());
                }
            }
            assert!(!root.path().join("audit.ndjson").exists());
        }
    }

    #[test]
    fn serving_preflight_accepts_present_secrets_without_a_migration_credential() {
        let (root, runtime) = setup();
        let config = load_runtime_config(&runtime).unwrap();
        let resolver = secret_resolver(&config).unwrap();
        config.check_runtime_secrets(&resolver).unwrap();
        assert!(!root.path().join("secrets/absent-migration-url").exists());
        assert!(!root.path().join("audit.ndjson").exists());
    }

    #[test]
    fn serving_preflight_names_all_unusable_secrets_without_printing_values() {
        for condition in ["mode", "empty", "nul", "oversized", "symlink"] {
            let (root, runtime) = setup();
            let audit = root.path().join("secrets/audit-key");
            match condition {
                "mode" => write_secret(&audit, CANARY.as_bytes(), 0o644),
                "empty" => write_secret(&audit, b"", 0o600),
                "nul" => write_secret(&audit, format!("{CANARY}\0").as_bytes(), 0o600),
                "oversized" => write_secret(
                    &audit,
                    &vec![b'x'; registry_platform_config::MAX_SECRET_BYTES + 1],
                    0o600,
                ),
                "symlink" => {
                    let outside = root.path().join("outside-secret");
                    write_secret(&outside, CANARY.as_bytes(), 0o600);
                    fs::remove_file(&audit).unwrap();
                    std::os::unix::fs::symlink(outside, &audit).unwrap();
                }
                _ => unreachable!(),
            }
            fs::remove_file(root.path().join("secrets/completion-token")).unwrap();
            let config = load_runtime_config(&runtime).unwrap();
            let resolver = secret_resolver(&config).unwrap();
            let report = config.check_runtime_secrets(&resolver).unwrap_err();
            let paths = report
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.path.as_str())
                .collect::<Vec<_>>();
            assert_eq!(
                paths,
                [
                    "/audit/hashKeyRef",
                    "/reviewCompletionDestinations/receiver/bearerTokenRef"
                ],
                "{condition}"
            );
            for shown in [report.render_human(), report.to_json_value().to_string()] {
                assert!(!shown.contains(CANARY), "{condition}: {shown}");
                assert!(!shown.contains("secret:file/"), "{condition}: {shown}");
            }
        }
    }
}
