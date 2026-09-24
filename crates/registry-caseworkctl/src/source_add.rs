// SPDX-License-Identifier: Apache-2.0

use crate::SourceAddArgs;
use anyhow::{bail, Context, Result};
use registry_casework_breg::MAXIMUM_REQUEST_ENTITIES;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_PROVIDER_OUTPUT: usize = 2 * 1024 * 1024;
// Keep the generated local teaching identities within bregctl's closed v1
// dev-client format before source add offers to write them.
const MAX_BREG_DEV_CLIENTS: usize = 32;
const MAX_BREG_DEV_CLIENT_SCOPES: usize = 32;
const MAX_BREG_DEV_CLIENT_CLAIMS: usize = 32;

/// The casework-reader access profile's identity: the client id, access
/// profile id, required scope, required purpose, and principal claim name
/// `candidate_fragments` authors into the BReg project. The local dev client
/// that exercises the profile, and the Casework clients that act through it,
/// read these same constants so neither can name a different one.
const READER_CLIENT_ID: &str = "casework-reader";
const READER_PRINCIPAL_CLAIM: &str = "registry_principal";
const READER_SCOPE: &str = "casework:source-reader";
const READER_PURPOSE: &str = "casework-sync";
const ACTOR_KIND_CLAIM: &str = "registry_actor_kind";
const SERVICE_ACTOR_KIND: &str = "service";
/// The issuer claim a local BReg client's access token carries its purpose under.
const PURPOSE_CLAIM: &str = "registry_purpose";

pub(super) fn run(args: &SourceAddArgs) -> Result<Value> {
    validate_id(&args.source_id)?;
    let registry = canonical_dir(&args.registry, "BReg project")?;
    let project = canonical_dir(&args.project, "Casework project")?;
    let description_path = configured_source_description_path(&project, &args.source_id)?;
    check_version(&args.bregctl_bin)?;
    let checked = invoke(&args.bregctl_bin, &["--format", "json", "check"], &registry)?;
    require_ok("check", &checked)?;
    let explained = invoke(
        &args.bregctl_bin,
        &["--format", "json", "explain", "change-requests"],
        &registry,
    )?;
    require_ok("explain change-requests", &explained)?;
    let registry_yaml = registry.join("registry.yaml");
    let bytes = fs::read(&registry_yaml).context("reading BReg registry.yaml")?;
    if bytes.len() > MAX_PROVIDER_OUTPUT {
        bail!("BReg registry.yaml exceeds the source-add byte limit");
    }
    let mut authored: Value = serde_norway::from_slice(&bytes)
        .context("parsing BReg registry.yaml without duplicate or custom YAML values")?;
    let registry_id = authored
        .pointer("/registry/id")
        .and_then(Value::as_str)
        .context("BReg registry.yaml has no registry.id")?
        .to_owned();
    if args.source_id != registry_id {
        bail!(
            "Casework source id must equal BReg registry.id so review subjects and source-context lookup use one namespace"
        );
    }
    let requests = select_requests(&project, &args.source_id, &registry_id, &explained)?;
    let mut findings = check_unpaired_review_policies(
        &project,
        &authored,
        requests[0].entity(),
        &requests[0].authority,
    )?;
    let readers = requests
        .iter()
        .map(|request| {
            let entity = request.entity();
            let projection =
                source_projection(&project, &args.source_id, entity, request.metadata)?;
            Ok((
                entity.to_owned(),
                reader_grant(request.metadata, &projection)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let (changes, proposed) = apply_breg_candidates(&mut authored, &bytes, &readers)?;
    let candidate_explanation = verify_candidate(&args.bregctl_bin, &registry, &proposed)?;
    let candidate_requests = select_requests(
        &project,
        &args.source_id,
        &registry_id,
        &candidate_explanation,
    )?;
    let dev_clients_plan =
        plan_breg_dev_clients(&registry, &project, &authored, &candidate_requests)?;
    findings.extend(dev_clients_plan.findings.iter().cloned());
    let description =
        source_description(&args.source_id, &candidate_requests, &candidate_explanation)?;
    let binding_path = project
        .join("sources")
        .join(format!("{}.breg-runtime.yaml", args.source_id));
    require_distinct_output_paths(&description_path, &binding_path)?;
    let binding = runtime_binding(&args.source_id, &registry_id, &candidate_requests)?;
    let mut breg_authoring_changes = changes;
    if let Value::Array(dev_clients_changes) = &dev_clients_plan.changes {
        breg_authoring_changes.extend(dev_clients_changes.iter().cloned());
    }
    let mut authoring_patch = authoring_patch(&readers);
    authoring_patch["devClients"] = dev_clients_plan.patch.clone();
    let mut report = json!({
        "ok": true,
        "command": "source add",
        "status": if args.apply { "applied" } else { "preview" },
        "sourceId": args.source_id,
        "registry": registry,
        "project": project,
        "sourceDescription": description_path,
        "bregRuntimeBinding": binding_path,
        "connection": connection_report(&candidate_requests),
        "bregAuthoringChanges": breg_authoring_changes,
        "bregAuthoringPatch": authoring_patch,
        "findings": findings,
        "activation": "not_performed",
        "next": if args.apply {
            json!(["Review the generated BReg webhook binding and provision its secret reference. Configure the Casework source reader with the actual issuer tokenEndpoint, clientAssertionAudience, resource and scopes before activating through each product's normal path.", "Run caseworkctl doctor --runtime-config FILE after authenticated directory setup."])
        } else {
            json!(["Review these exact local changes, then repeat source add with --apply."])
        }
    });
    if !dev_clients_plan.warnings.is_empty() {
        report["warnings"] = json!(dev_clients_plan.warnings);
    }
    if !args.apply {
        report["candidateRuntimeBinding"] = serde_norway::from_str(&binding)?;
        return Ok(report);
    }
    require_absent_or_exact_json(&description_path, &description)?;
    require_absent_or_exact(&binding_path, binding.as_bytes())?;
    if fs::read(&registry_yaml).context("re-reading BReg registry.yaml before apply")? != bytes {
        bail!("BReg registry.yaml changed after preview; no files were written, retry source add against its current revision");
    }
    if let Some(write) = &dev_clients_plan.write {
        if fs::read(&write.path).context("re-reading BReg dev-clients.yaml before apply")?
            != write.original
        {
            bail!("BReg dev-clients.yaml changed after preview; no files were written, retry source add against its current revision");
        }
    }
    ensure_runtime_binding_parent(&project, &binding_path)?;
    fs::create_dir_all(description_path.parent().expect("source file has parent"))
        .context("creating Casework source directory")?;
    write_atomic(&registry_yaml, proposed.as_bytes())?;
    write_json_atomic(&description_path, &description)?;
    write_atomic(&binding_path, binding.as_bytes())?;
    if let Some(write) = &dev_clients_plan.write {
        write_atomic(&write.path, write.proposed.as_bytes())?;
    }
    let final_check = invoke(&args.bregctl_bin, &["--format", "json", "check"], &registry)?;
    require_ok("check after apply", &final_check)?;
    Ok(report)
}

fn require_distinct_output_paths(description_path: &Path, binding_path: &Path) -> Result<()> {
    if description_path == binding_path {
        bail!("source description path must not be the BReg runtime binding path");
    }
    Ok(())
}

/// Prepare the fixed launcher-binding directory without following an authored
/// symlink outside the canonical Casework project. This runs before any output
/// file is published so a missing directory cannot leave a partial apply.
fn ensure_runtime_binding_parent(project: &Path, binding_path: &Path) -> Result<()> {
    let parent = binding_path
        .parent()
        .context("BReg runtime binding has no parent")?;
    if parent != project.join("sources") {
        bail!("BReg runtime binding must stay in the Casework sources directory");
    }
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("Casework sources directory must not be a symlink")
        }
        Ok(metadata) if !metadata.is_dir() => {
            bail!("Casework sources path must be a directory")
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(parent).context("creating Casework runtime-binding directory")?;
        }
        Err(error) => return Err(error).context("checking Casework sources directory"),
    }
    if fs::canonicalize(parent).context("resolving Casework sources directory")? != parent {
        bail!("Casework sources directory must resolve inside the project");
    }
    Ok(())
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_lowercase()
            } else {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
            }
        })
    {
        bail!("source id must be a lowercase local identifier of at most 64 characters");
    }
    Ok(())
}

/// Resolve a source import from the authored Casework declaration. The project
/// directory is already canonical, so rejecting non-normal and symlinked path
/// components keeps creation inside that directory even before the file exists.
fn configured_source_description_path(project: &Path, source_id: &str) -> Result<PathBuf> {
    let policy = crate::project::load_and_check_policy(project)?;
    let description = &policy
        .sources
        .iter()
        .find(|source| source.id == source_id)
        .with_context(|| format!("Casework project does not declare source {source_id}"))?
        .description;
    let relative = Path::new(description);
    if description.is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("source description path must be a normalized path inside the project");
    }

    let mut candidate = project.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(std::path::Component::Normal(component)) = components.next() {
        candidate.push(component);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("source description path must not contain symlinks")
            }
            Ok(metadata) if components.peek().is_some() && !metadata.is_dir() => {
                bail!("source description parent must be a directory")
            }
            Ok(metadata) if components.peek().is_none() && !metadata.is_file() => {
                bail!("source description path must be a regular file when it exists")
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("checking source description path {}", candidate.display())
                })
            }
        }
    }
    Ok(candidate)
}

fn canonical_dir(path: &Path, label: &str) -> Result<PathBuf> {
    let path = fs::canonicalize(path).with_context(|| format!("resolving {label}"))?;
    if !fs::metadata(&path)?.is_dir() {
        bail!("{label} must be a directory");
    }
    Ok(path)
}

fn check_version(binary: &Path) -> Result<()> {
    let output = Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .context("starting bregctl; use --bregctl-bin or BREGCTL_BIN to select it")?;
    let expected = format!("bregctl {}", registry_platform_buildinfo::DISPLAY_VERSION);
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != expected {
        bail!("source add requires {expected}");
    }
    Ok(())
}

fn invoke(binary: &Path, prefix: &[&str], project: &Path) -> Result<Value> {
    let mut arguments = prefix.iter().map(OsString::from).collect::<Vec<_>>();
    arguments.push(project.as_os_str().to_owned());
    let output = Command::new(binary)
        .args(&arguments)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("starting bregctl {}", prefix.join(" ")))?;
    if output.stdout.len() > MAX_PROVIDER_OUTPUT {
        bail!("bregctl {} exceeded its output limit", prefix.join(" "));
    }
    let report: Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("bregctl {} returned invalid public JSON", prefix.join(" ")))?;
    if !output.status.success() {
        return Err(provider_refusal(prefix, &report));
    }
    Ok(report)
}

fn provider_refusal(operation: &[&str], report: &Value) -> anyhow::Error {
    let messages = report["diagnostics"]
        .as_array()
        .into_iter()
        .flatten()
        .take(8)
        .filter_map(|item| {
            Some(format!(
                "{}: {}",
                item["code"].as_str()?,
                item["message"].as_str()?
            ))
        })
        .collect::<Vec<_>>();
    anyhow::anyhow!(
        "bregctl {} refused: {}",
        operation.join(" "),
        messages.join("; ")
    )
}

fn require_ok(operation: &str, report: &Value) -> Result<()> {
    if report["ok"] != true {
        bail!("bregctl {operation} did not return a successful public report");
    }
    Ok(())
}

/// The scopes and purpose a Casework staff or supervisor dev client inherits
/// from the selected BReg request's review and apply access profiles, plus
/// any finding raised because a profile's rowBoundaries claims are not
/// reflected in the local dev-client export.
#[derive(Debug)]
struct ReviewerAuthority {
    profiles: BTreeSet<String>,
    scopes: BTreeSet<String>,
    purpose: Option<String>,
    row_boundary_findings: Vec<Value>,
    /// Access profiles that also admit requester clients outside this Casework
    /// project. Those clients can act on the request without Casework.
    warnings: Vec<String>,
}

/// What it takes to write a planned set of BReg local dev clients back to the
/// project's `dev-clients.yaml`, captured at preview time so apply can refuse
/// a file that has since changed.
#[derive(Debug)]
struct DevClientsWrite {
    path: PathBuf,
    original: Vec<u8>,
    proposed: String,
}

/// The outcome of planning the BReg `dev-clients.yaml` side of `source add`:
/// the exact clients for the preview report, the authoring changes they
/// correspond to, what apply needs to write it when the BReg project has a
/// dev-clients.yaml to patch, and any non-fatal findings the plan raised
/// (for example, a reviewer access profile whose rowBoundaries claims the
/// local dev-client export does not add).
#[derive(Debug)]
struct DevClientsPlan {
    patch: Value,
    changes: Value,
    write: Option<DevClientsWrite>,
    findings: Vec<Value>,
    warnings: Vec<String>,
}

struct SelectedRequest<'a> {
    metadata: &'a Value,
    authority: String,
    policy_id: String,
    producer_id: String,
    producer_profile: String,
    recovery_days: u64,
    completion: Option<CompletionPlan>,
    application: ApplicationPlan,
}

struct CompletionPlan {
    destination_id: String,
    recipient_binding: String,
}

enum ApplicationPlan {
    Manual,
    Automatic {
        executor: String,
        access_profile: String,
    },
}

impl SelectedRequest<'_> {
    fn entity(&self) -> &str {
        self.metadata["requestEntity"]
            .as_str()
            .expect("validated entity")
    }

    fn connection_report(&self) -> Value {
        let application = match &self.application {
            ApplicationPlan::Manual => json!({"mode":"manual"}),
            ApplicationPlan::Automatic {
                executor,
                access_profile,
            } => json!({
                "mode":"automatic",
                "executor":executor,
                "accessProfile":access_profile,
            }),
        };
        json!({
            "policy":{"authority":self.authority,"kind":self.policy_id},
            "producerAdmission":{
                "producerId":self.producer_id,
                "profile":self.producer_profile,
                "recoveryDays":self.recovery_days,
                "completion":self.completion.as_ref().map(|completion| json!({
                    "destinationId":completion.destination_id,
                    "recipientBinding":completion.recipient_binding,
                })),
            },
            "application":application,
        })
    }
}

/// One request entity keeps the single connection object; several list each
/// entity's connection under `requests`.
fn connection_report(requests: &[SelectedRequest<'_>]) -> Value {
    if let [request] = requests {
        return request.connection_report();
    }
    let requests = requests
        .iter()
        .map(|request| {
            let mut connection = request.connection_report();
            connection["entity"] = json!(request.entity());
            connection
        })
        .collect::<Vec<_>>();
    json!({ "requests": requests })
}

/// Select every request entity the Casework source declares, in declaration
/// order, from the BReg compiled request metadata.
fn select_requests<'a>(
    project: &Path,
    source_id: &str,
    registry_id: &str,
    report: &'a Value,
) -> Result<Vec<SelectedRequest<'a>>> {
    let policy = load_casework_policy(project)?;
    let configured = policy["sources"]
        .as_array()
        .and_then(|sources| sources.iter().find(|source| source["id"] == source_id))
        .context("source id is not declared in casework.yaml")?;
    if configured["adapter"] != "breg" {
        bail!("source add currently supports only a declared breg adapter");
    }
    let requests = configured["requests"]
        .as_array()
        .context("source must declare requests")?;
    if requests.is_empty() || requests.len() > MAXIMUM_REQUEST_ENTITIES {
        bail!("source must declare between 1 and {MAXIMUM_REQUEST_ENTITIES} request entities");
    }
    let mut declared_entities = BTreeSet::new();
    requests
        .iter()
        .map(|declared| {
            let entity = declared["entity"]
                .as_str()
                .context("source request entity is missing")?;
            if !declared_entities.insert(entity) {
                bail!("source declares request entity {entity} more than once");
            }
            select_request(&policy, registry_id, entity, report)
                .with_context(|| format!("pairing request entity {entity}"))
        })
        .collect()
}

fn select_request<'a>(
    policy: &Value,
    registry_id: &str,
    entity: &str,
    report: &'a Value,
) -> Result<SelectedRequest<'a>> {
    let choices = report
        .pointer("/explanation/requests")
        .and_then(Value::as_array)
        .context("BReg explanation omitted requests")?;
    let selected = choices
        .iter()
        .find(|candidate| candidate["requestEntity"] == entity)
        .context("declared request entity is absent from BReg compiled metadata")?;
    let review = selected["review"]
        .as_object()
        .context("BReg request review binding is absent")?;
    let authority = review
        .get("authority")
        .and_then(Value::as_str)
        .context("BReg request must name a Casework review authority")?;
    let policy_id = review
        .get("policyId")
        .and_then(Value::as_str)
        .context("BReg request must name a Casework review policy")?;
    if review.len() != 2 {
        bail!("BReg request review binding contains unsupported members");
    }
    let review_kind = policy["reviewKinds"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|kind| kind["id"] == policy_id)
        .context("BReg review policy is not declared in casework.yaml")?;
    if review_kind["purpose"] != "approval" || review_kind["contextStrategy"] != "source" {
        bail!("BReg review policy must be a source-context approval kind");
    }
    let producers = policy["reviewProducers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|producer| {
            producer["sourceNamespaces"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == registry_id))
                && producer["kinds"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|value| value == policy_id))
        })
        .collect::<Vec<_>>();
    let [producer] = producers.as_slice() else {
        bail!("casework.yaml must admit exactly one producer for the BReg registry id and review policy");
    };
    let producer_id = producer["id"]
        .as_str()
        .context("Casework review producer id is missing")?;
    let producer_profile = producer["profile"]
        .as_str()
        .context("Casework review producer profile is missing")?;
    let recovery_days = producer["recoveryDays"]
        .as_u64()
        .context("Casework review producer recoveryDays is missing")?;
    let completion = producer
        .get("completion")
        .map(|completion| -> Result<CompletionPlan> {
            Ok(CompletionPlan {
                destination_id: completion["destinationId"]
                    .as_str()
                    .context("Casework completion destinationId is missing")?
                    .to_owned(),
                recipient_binding: completion["recipientBinding"]
                    .as_str()
                    .context("Casework completion recipientBinding is missing")?
                    .to_owned(),
            })
        })
        .transpose()?;
    let on_approved = selected["onApproved"]
        .as_object()
        .context("BReg request onApproved binding is absent")?;
    let application = match on_approved.get("mode").and_then(Value::as_str) {
        Some("manual") if on_approved.len() == 1 => ApplicationPlan::Manual,
        Some("automatic") if on_approved.len() == 2 => {
            let executor = on_approved
                .get("executor")
                .and_then(Value::as_str)
                .context("automatic BReg application must name an executor")?;
            let profiles = selected["applyPermissions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|permission| permission["profile"].as_str())
                .collect::<BTreeSet<_>>();
            let mut profiles = profiles.into_iter();
            let access_profile = profiles
                .next()
                .context("automatic BReg application has no apply access profile")?;
            if profiles.next().is_some() {
                bail!("automatic BReg application has more than one apply access profile; choose one before generating an executor binding");
            }
            ApplicationPlan::Automatic {
                executor: executor.to_owned(),
                access_profile: access_profile.to_owned(),
            }
        }
        _ => bail!("BReg onApproved must select manual application or one automatic executor"),
    };
    Ok(SelectedRequest {
        metadata: selected,
        authority: authority.to_owned(),
        policy_id: policy_id.to_owned(),
        producer_id: producer_id.to_owned(),
        producer_profile: producer_profile.to_owned(),
        recovery_days,
        completion,
        application,
    })
}

/// select_request already refuses an unresolvable review.policyId on the one
/// BReg change-request entity this invocation is pairing. A BReg registry.yaml
/// can declare other change-request entities that name the same review
/// authority (the one this Casework project was just proven to own) but that
/// are not paired to any source: those entities pass BReg's own compile
/// check, since it only validates that authority and policyId are well-formed
/// identifiers, not that a bound review authority actually declares that
/// policy. source add is the only place both projects are read together, so
/// it is where that gap is caught.
///
/// A sibling entity that fails this check is reported as a finding, not a
/// refusal, unlike the paired entity's own check in select_request: pairing
/// one entity before another entity's review kind exists is ordinary
/// incremental authoring, and more than one Casework project can legitimately
/// share a review authority id, so an unresolved policyId here may simply
/// belong to a different Casework project. A sibling whose policyId is
/// missing or not a string never reaches this check: `bregctl check` refuses
/// it first. Only root registry.yaml entities are scanned; entities a locked
/// module contributes are not.
fn check_unpaired_review_policies(
    project: &Path,
    authored: &Value,
    paired_entity: &str,
    authority: &str,
) -> Result<Vec<Value>> {
    let policy = load_casework_policy(project)?;
    let review_kind_ids: BTreeSet<&str> = policy["reviewKinds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|kind| kind["id"].as_str())
        .collect();
    let entities = authored["entities"]
        .as_array()
        .context("BReg registry.yaml has no entities")?;
    let mut findings = Vec::new();
    for (index, entity) in entities.iter().enumerate() {
        let Some(entity_id) = entity["id"].as_str() else {
            continue;
        };
        if entity_id == paired_entity {
            continue;
        }
        let Some(review) = entity.pointer("/changeRequest/review") else {
            continue;
        };
        if review["authority"] != authority {
            continue;
        }
        match review.get("policyId").and_then(Value::as_str) {
            Some(policy_id) if review_kind_ids.contains(policy_id) => {}
            Some(policy_id) => findings.push(unresolved_review_policy_finding(
                index, entity_id, authority, policy_id,
            )),
            // `bregctl check` already refused a missing or non-string
            // policyId, since BReg reads it as a required string.
            None => {}
        }
    }
    Ok(findings)
}

/// A finding warning that a BReg change-request entity other than the one
/// being paired names this Casework project's review authority with a
/// `policyId` no declared `reviewKinds[].id` matches. BReg's own compile
/// check does not catch this, since it only validates that `policyId` is a
/// well-formed identifier, not that the named authority actually declares
/// it.
fn unresolved_review_policy_finding(
    index: usize,
    entity_id: &str,
    authority: &str,
    policy_id: &str,
) -> Value {
    json!({
        "severity": "finding",
        "code": "casework.source-add.review-policy-unresolved",
        "artifact": "breg_entity",
        "path": format!("registry.yaml:/entities/{index}/changeRequest/review/policyId"),
        "message": format!(
            "BReg change-request entity {entity_id} declares review authority {authority} with policyId {policy_id}, but casework.yaml has no reviewKinds[].id matching {policy_id}"
        ),
        "suggestedAction": format!(
            "Add a reviewKinds[].id matching {policy_id} to casework.yaml, or correct entity {entity_id}'s changeRequest.review.policyId, before pairing a source for it."
        ),
    })
}

fn source_projection(
    project: &Path,
    source_id: &str,
    entity: &str,
    metadata: &Value,
) -> Result<Vec<String>> {
    let policy = load_casework_policy(project)?;
    let source = policy["sources"]
        .as_array()
        .and_then(|sources| sources.iter().find(|source| source["id"] == source_id))
        .context("source id is not declared in casework.yaml")?;
    let configured = source["requests"]
        .as_array()
        .and_then(|requests| requests.iter().find(|request| request["entity"] == entity))
        .context("source request entity is not declared in casework.yaml")?;
    let mut projection: Vec<String> = match configured.get("projection") {
        None => Vec::new(),
        Some(value) => serde_json::from_value(value.clone())
            .context("source projection must be a list of field identifiers")?,
    };
    if projection.len() > registry_casework_core::MAXIMUM_ROUTING_PROJECTION_FIELDS
        || projection
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != projection.len()
    {
        bail!("source projection must contain at most 32 distinct fields");
    }
    for field in &projection {
        if !metadata["fields"].as_array().is_some_and(|fields| {
            fields
                .iter()
                .any(|descriptor| descriptor["field"] == *field)
        }) {
            bail!("source projection references a field absent from BReg compiled metadata");
        }
    }
    if let Some(reference) = configured.get("displayReference") {
        let field = reference
            .get("field")
            .and_then(Value::as_str)
            .context("displayReference.field must name one source string field")?;
        let descriptor = metadata["fields"]
            .as_array()
            .and_then(|fields| {
                fields
                    .iter()
                    .find(|descriptor| descriptor["field"] == field)
            })
            .context("displayReference.field is absent from BReg compiled metadata")?;
        let schema = &descriptor["schema"];
        if schema["type"] != "string" {
            bail!("displayReference.field must be a string");
        }
        projection.push(field.to_owned());
    }
    Ok(projection)
}

/// What the casework-reader profile may read on the request entity, and the one
/// field the lifecycle event carries. BReg requires an event projection of at
/// least one field; the adapter discards its value and reads the request
/// through the reader, so the event carries a field the reader already sees.
struct ReaderGrant {
    fields: Vec<String>,
    event_field: String,
}

/// The reader reads every request field that names an existing target record,
/// whatever the model calls it, plus the Casework projection. A request that
/// only creates records has no target field, so its event carries the first
/// projected field instead.
fn reader_grant(metadata: &Value, projection: &[String]) -> Result<ReaderGrant> {
    let declared = metadata["effects"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|effect| &effect["target"]["binding"]);
    let planned = metadata
        .pointer("/planner/possibleWrites")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|write| &write["target"]);
    let targets = declared
        .chain(planned)
        .filter(|target| target["kind"] == "existing")
        .filter_map(|target| target.pointer("/fromField/field").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let event_field = targets
        .first()
        .or_else(|| projection.first())
        .context("the BReg request names no existing target record and the Casework source declares no projection; add a projection field so the lifecycle event has a field to carry")?
        .clone();
    let fields = targets
        .into_iter()
        .chain(projection.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(ReaderGrant {
        fields,
        event_field,
    })
}

fn load_casework_policy(project: &Path) -> Result<Value> {
    let bytes = fs::read(project.join("casework.yaml")).context("reading casework.yaml")?;
    let root: Value = serde_norway::from_slice(&bytes).context("parsing casework.yaml")?;
    Ok(root)
}

/// Pair every request entity with the lifecycle hook and the shared reader
/// profile. Each pass patches the text the previous pass rendered, so every
/// narrow YAML patch is checked against the authored state it produced.
fn apply_breg_candidates(
    root: &mut Value,
    original: &[u8],
    readers: &[(String, ReaderGrant)],
) -> Result<(Vec<Value>, String)> {
    let mut changes: Vec<Value> = Vec::new();
    let mut text = std::str::from_utf8(original)
        .context("BReg registry.yaml must be UTF-8")?
        .to_owned();
    for (entity, reader) in readers {
        let applied = apply_breg_candidate(root, entity, reader)?;
        for change in applied.as_array().into_iter().flatten() {
            if !changes.contains(change) {
                changes.push(change.clone());
            }
        }
        text = render_candidate_preserving_authored_text(text.as_bytes(), entity, root, reader)?;
    }
    Ok((changes, text))
}

fn apply_breg_candidate(root: &mut Value, entity_id: &str, reader: &ReaderGrant) -> Result<Value> {
    let object = root
        .as_object_mut()
        .context("BReg registry.yaml must contain an object")?;
    let entities = object
        .get_mut("entities")
        .and_then(Value::as_array_mut)
        .context("BReg registry.yaml has no entities")?;
    let entity = entities
        .iter_mut()
        .find(|item| item["id"] == entity_id)
        .context("BReg entity disappeared from authored project")?;
    let entity_object = entity
        .as_object_mut()
        .context("BReg entity must be an object")?;
    let hooks = entity_object
        .entry("hooks")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("BReg entity hooks must be an array")?;
    let (hook, profile) = candidate_fragments(entity_id, reader);
    match hooks
        .iter()
        .find(|item| item["id"] == "casework-lifecycle-v1")
    {
        Some(existing) if existing != &hook => {
            bail!("BReg hook casework-lifecycle-v1 already exists with different content")
        }
        None => hooks.push(hook),
        _ => {}
    }
    let profiles = object
        .get_mut("accessProfiles")
        .and_then(Value::as_array_mut)
        .context("BReg registry.yaml has no accessProfiles")?;
    // One reader profile serves every Casework pairing on this registry; each
    // pairing adds the permission for its own request entity.
    match profiles
        .iter_mut()
        .find(|item| item["id"] == READER_CLIENT_ID)
    {
        None => profiles.push(profile),
        Some(existing) => {
            let permission = profile["permissions"][0].clone();
            let shape = |value: &Value| {
                let mut value = value.clone();
                value["permissions"] = json!([]);
                value
            };
            if shape(existing) != shape(&profile) {
                bail!(
                    "BReg access profile {READER_CLIENT_ID} already exists with different content"
                )
            }
            let permissions = existing["permissions"].as_array_mut().with_context(|| {
                format!("BReg access profile {READER_CLIENT_ID} permissions must be a list")
            })?;
            match permissions.iter().find(|item| item["entity"] == entity_id) {
                Some(existing) if existing != &permission => bail!(
                    "BReg access profile {READER_CLIENT_ID} already grants {entity_id} with different content"
                ),
                None => permissions.push(permission),
                _ => {}
            }
        }
    }
    Ok(json!([
        {"file":"registry.yaml","path":format!("/entities/{entity_id}/hooks/casework-lifecycle-v1"),"operation":"ensure_exact"},
        {"file":"registry.yaml","path":format!("/accessProfiles/{READER_CLIENT_ID}"),"operation":"ensure_exact"}
    ]))
}

fn candidate_fragments(entity_id: &str, reader: &ReaderGrant) -> (Value, Value) {
    let fields = &reader.fields;
    (
        json!({"id":"casework-lifecycle-v1","phase":"after","trigger":"request_lifecycle","projection":[reader.event_field],"handler":{"kind":"url","destinationId":"casework"}}),
        json!({
            "id":READER_CLIENT_ID, "default":false, "principalClaim":READER_PRINCIPAL_CLAIM,
            "requiredScopes":[READER_SCOPE], "requiredPurposes":[READER_PURPOSE],
            "permissions":[{"entity":entity_id,"operations":["get","list"],"readableFields":fields,"readableRequestFields":["review_state"],"rowBoundaries":[]}]
        }),
    )
}

/// The report's view of the BReg authoring fragments. One request entity keeps
/// the single `event` member; several list each entity's hook under `events`.
/// The access profile carries every paired entity's permission.
fn authoring_patch(readers: &[(String, ReaderGrant)]) -> Value {
    let fragments = readers
        .iter()
        .map(|(entity, reader)| (entity, candidate_fragments(entity, reader)))
        .collect::<Vec<_>>();
    let mut profile = fragments
        .first()
        .map(|(_, (_, profile))| profile.clone())
        .unwrap_or(Value::Null);
    if let [(_, (hook, _))] = fragments.as_slice() {
        return json!({"event": hook, "accessProfile": profile});
    }
    profile["permissions"] = fragments
        .iter()
        .flat_map(|(_, (_, profile))| {
            profile["permissions"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    let events = fragments
        .iter()
        .map(|(entity, (hook, _))| ((*entity).clone(), hook.clone()))
        .collect::<serde_json::Map<_, _>>();
    json!({"events": events, "accessProfile": profile})
}

fn render_candidate_preserving_authored_text(
    original: &[u8],
    entity_id: &str,
    expected: &Value,
    reader: &ReaderGrant,
) -> Result<String> {
    let text = std::str::from_utf8(original).context("BReg registry.yaml must be UTF-8")?;
    if text.trim_start().starts_with('{') {
        // JSON authoring has no comment syntax. Pretty-printing this branch keeps
        // every parsed key while avoiding a misleading claim about preserving
        // comments that JSON cannot contain.
        let mut rendered = serde_json::to_string_pretty(expected)?;
        rendered.push('\n');
        return Ok(rendered);
    }
    let parsed: Value = serde_norway::from_str(text)?;
    let has_hook = parsed["entities"]
        .as_array()
        .and_then(|entities| entities.iter().find(|entity| entity["id"] == entity_id))
        .and_then(|entity| entity["hooks"].as_array())
        .is_some_and(|hooks| {
            hooks
                .iter()
                .any(|hook| hook["id"] == "casework-lifecycle-v1")
        });
    let profile = parsed["accessProfiles"].as_array().and_then(|profiles| {
        profiles
            .iter()
            .find(|profile| profile["id"] == READER_CLIENT_ID)
    });
    let has_permission = profile
        .and_then(|profile| profile["permissions"].as_array())
        .is_some_and(|permissions| {
            permissions
                .iter()
                .any(|permission| permission["entity"] == entity_id)
        });
    let mut rendered = text.to_owned();
    if !has_hook {
        rendered = insert_entity_hook(&rendered, entity_id, &reader.event_field)?;
    }
    if profile.is_none() {
        rendered = insert_access_profile(&rendered, entity_id, reader)?;
    } else if !has_permission {
        rendered = insert_reader_permission(&rendered, entity_id, reader)?;
    }
    let round_trip: Value =
        serde_norway::from_str(&rendered).context("parsing narrow BReg YAML patch")?;
    if &round_trip != expected {
        bail!("narrow BReg YAML patch changed unexpected authored content; no files were written");
    }
    Ok(rendered)
}

fn insert_entity_hook(text: &str, entity_id: &str, event_field: &str) -> Result<String> {
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    let marker = format!("- id: {entity_id}");
    let start = lines
        .iter()
        .position(|line| line.trim() == marker)
        .context("narrow YAML patch could not locate the declared BReg entity")?;
    let item_indent = leading_spaces(lines[start]);
    let next_item = (start + 1..lines.len()).find(|index| {
        leading_spaces(lines[*index]) == item_indent
            && lines[*index].trim_start().starts_with("- id:")
    });
    let section_end = (start + 1..lines.len()).find(|index| {
        leading_spaces(lines[*index]) < item_indent && !lines[*index].trim().is_empty()
    });
    let end = next_item
        .into_iter()
        .chain(section_end)
        .min()
        .unwrap_or(lines.len());
    let field_indent = item_indent + 2;
    let hooks = (start + 1..end).find(|index| {
        leading_spaces(lines[*index]) == field_indent && lines[*index].trim() == "hooks:"
    });
    let insertion = if let Some(hooks) = hooks {
        (hooks + 1..end)
            .find(|index| {
                leading_spaces(lines[*index]) == field_indent
                    && !lines[*index].trim().is_empty()
                    && !lines[*index].trim_start().starts_with('#')
            })
            .unwrap_or(end)
    } else {
        end
    };
    let block = if hooks.is_some() {
        format!("{}- id: casework-lifecycle-v1\n{}  phase: after\n{}  trigger: request_lifecycle\n{}  projection: [{event_field}]\n{}  handler: {{kind: url, destinationId: casework}}\n", " ".repeat(field_indent + 2), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2))
    } else {
        format!("{}hooks:\n{}- id: casework-lifecycle-v1\n{}  phase: after\n{}  trigger: request_lifecycle\n{}  projection: [{event_field}]\n{}  handler: {{kind: url, destinationId: casework}}\n", " ".repeat(field_indent), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2))
    };
    Ok(insert_at_line(&lines, insertion, &block))
}

fn insert_access_profile(text: &str, entity_id: &str, reader: &ReaderGrant) -> Result<String> {
    let permission = reader_permission_yaml(6, entity_id, reader)?;
    let block = format!("  - id: {READER_CLIENT_ID}\n    default: false\n    principalClaim: {READER_PRINCIPAL_CLAIM}\n    requiredScopes: [{READER_SCOPE}]\n    requiredPurposes: [{READER_PURPOSE}]\n    permissions:\n{permission}");
    insert_yaml_collection_items(text, "accessProfiles", "[]", &block)
}

fn reader_permission_yaml(indent: usize, entity_id: &str, reader: &ReaderGrant) -> Result<String> {
    let fields = serde_json::to_string(&reader.fields)?;
    let pad = " ".repeat(indent);
    Ok(format!("{pad}- entity: {entity_id}\n{pad}  operations: [get, list]\n{pad}  readableFields: {fields}\n{pad}  readableRequestFields: [review_state]\n{pad}  rowBoundaries: []\n"))
}

/// Append this entity's permission to the block `permissions` list of an
/// existing casework-reader profile, leaving every authored line in place.
fn insert_reader_permission(text: &str, entity_id: &str, reader: &ReaderGrant) -> Result<String> {
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    let significant = |line: &str| !line.trim().is_empty() && !line.trim_start().starts_with('#');
    let marker = format!("- id: {READER_CLIENT_ID}");
    let start = lines
        .iter()
        .position(|line| line.trim() == marker)
        .context("narrow YAML patch could not locate the casework-reader access profile")?;
    let item_indent = leading_spaces(lines[start]);
    let end = (start + 1..lines.len())
        .find(|index| significant(lines[*index]) && leading_spaces(lines[*index]) <= item_indent)
        .unwrap_or(lines.len());
    let key = (start + 1..end)
        .find(|index| {
            leading_spaces(lines[*index]) == item_indent + 2
                && lines[*index].trim_start().starts_with("permissions:")
        })
        .context("narrow YAML patch could not locate the casework-reader permissions")?;
    let value = lines[key]
        .trim()
        .trim_start_matches("permissions:")
        .trim_start();
    if !value.is_empty() && !value.starts_with('#') {
        bail!("narrow YAML patch supports a block permissions list on the casework-reader access profile");
    }
    let first_item = (key + 1..end)
        .find(|index| significant(lines[*index]))
        .filter(|index| lines[*index].trim_start().starts_with("- "))
        .context("narrow YAML patch could not locate the casework-reader permission items")?;
    let sequence_indent = leading_spaces(lines[first_item]);
    let insertion = (first_item + 1..end)
        .find(|index| {
            let line = lines[*index];
            significant(line)
                && (leading_spaces(line) < sequence_indent
                    || (leading_spaces(line) == sequence_indent
                        && !line.trim_start().starts_with('-')))
        })
        .unwrap_or(end);
    let block = reader_permission_yaml(sequence_indent, entity_id, reader)?;
    Ok(insert_at_line(&lines, insertion, &block))
}

fn insert_yaml_collection_items(
    text: &str,
    key: &str,
    empty_collection: &str,
    block: &str,
) -> Result<String> {
    let prefix = format!("{key}:");
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    let start = lines
        .iter()
        .position(|line| leading_spaces(line) == 0 && line.starts_with(&prefix))
        .with_context(|| format!("narrow YAML patch could not locate {key}"))?;
    let line = lines[start];
    let logical = line.trim_end_matches(['\r', '\n']);
    let value = logical
        .strip_prefix(&prefix)
        .expect("the selected line has the collection key")
        .trim_start();
    if let Some(suffix) = value.strip_prefix(empty_collection) {
        let trailing = suffix.trim_start();
        if trailing.is_empty() || trailing.starts_with('#') {
            let newline = if line.ends_with("\r\n") { "\r\n" } else { "\n" };
            let comment = if trailing.is_empty() {
                String::new()
            } else {
                format!(" {trailing}")
            };
            let header = format!("{prefix}{comment}{newline}");
            let mut output = String::with_capacity(text.len() + block.len());
            output.extend(lines[..start].iter().copied());
            output.push_str(&header);
            output.push_str(block);
            output.extend(lines[start + 1..].iter().copied());
            return Ok(output);
        }
    }
    if !value.is_empty() && !value.starts_with('#') {
        bail!("narrow YAML patch supports block {key} or an empty flow collection");
    }
    let end = (start + 1..lines.len())
        .find(|index| {
            leading_spaces(lines[*index]) == 0
                && !lines[*index].trim().is_empty()
                && !lines[*index].trim_start().starts_with('#')
        })
        .unwrap_or(lines.len());
    Ok(insert_at_line(&lines, end, block))
}

fn insert_at_line(lines: &[&str], index: usize, block: &str) -> String {
    let mut output =
        String::with_capacity(lines.iter().map(|line| line.len()).sum::<usize>() + block.len());
    output.extend(lines[..index].iter().copied());
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    output.push_str(block);
    output.extend(lines[index..].iter().copied());
    output
}

fn leading_spaces(line: &str) -> usize {
    line.bytes().take_while(|byte| *byte == b' ').count()
}

/// The local BReg service client exercising the casework-reader access profile,
/// with the same id, scope, purpose, and principal claim `candidate_fragments`
/// authors the profile itself with.
fn reader_dev_client() -> Value {
    json!({
        "id": READER_CLIENT_ID,
        "accessProfiles": [READER_CLIENT_ID],
        "scopes": [READER_SCOPE],
        "claims": {
            ACTOR_KIND_CLAIM: SERVICE_ACTOR_KIND,
            READER_PRINCIPAL_CLAIM: READER_CLIENT_ID,
            PURPOSE_CLAIM: READER_PURPOSE,
        },
    })
}

/// The scopes and purpose every Casework staff or supervisor dev client must
/// carry to act as a reviewer on the selected BReg request: the union of
/// `requiredScopes` from every distinct access profile named in its
/// `reviewPermissions`/`applyPermissions`, and the one `registry_purpose` those
/// restricted profiles must accept in common. Profiles with no
/// `requiredPurposes` restriction do not require the claim.
fn reviewer_authority(
    authored: &Value,
    request: &Value,
    reviewer_clients: &BTreeSet<String>,
) -> Result<ReviewerAuthority> {
    let profile_ids: BTreeSet<&str> = request["reviewPermissions"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(request["applyPermissions"].as_array().into_iter().flatten())
        .filter_map(|grant| grant["profile"].as_str())
        .collect();
    if profile_ids.is_empty() {
        bail!("the selected BReg request has no review or apply access profiles to bind a Casework reviewer through");
    }
    let profiles = authored["accessProfiles"]
        .as_array()
        .context("BReg registry.yaml has no accessProfiles")?;
    let mut scopes = BTreeSet::new();
    let mut allowed_purposes: Option<BTreeSet<String>> = None;
    let mut row_boundary_findings = Vec::new();
    let mut warnings = Vec::new();
    for id in &profile_ids {
        let (profile_index, profile) = profiles
            .iter()
            .enumerate()
            .find(|(_, candidate)| candidate["id"] == *id)
            .with_context(|| format!("BReg access profile {id} named by the selected request is absent from registry.yaml"))?;
        if profile["principalClaim"] != Value::String(READER_PRINCIPAL_CLAIM.to_owned()) {
            bail!("BReg access profile {id} does not authenticate its principal through {READER_PRINCIPAL_CLAIM}");
        }
        if profile["actorKind"] != "human" {
            bail!("BReg access profile {id} must declare actorKind human for Casework reviewers");
        }
        let requesters = profile["requesterClients"]
            .as_array()
            .with_context(|| format!("BReg access profile {id} must declare requesterClients"))?
            .iter()
            .map(|client| {
                client.as_str().map(str::to_owned).with_context(|| {
                    format!("BReg access profile {id} requesterClients must be strings")
                })
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if !reviewer_clients.is_subset(&requesters) {
            bail!("BReg access profile {id} requesterClients must include every Casework staff and supervisor client");
        }
        let others: Vec<&str> = requesters
            .difference(reviewer_clients)
            .map(String::as_str)
            .collect();
        if !others.is_empty() {
            warnings.push(format!(
                "BReg access profile {id} also admits requester clients outside this Casework project ({}); they can act on the request without Casework",
                others.join(", ")
            ));
        }
        let mut row_boundary_locations = Vec::new();
        collect_row_boundary_locations(profile, None, &mut Vec::new(), &mut row_boundary_locations);
        row_boundary_findings.extend(represent_row_boundary_locations(
            authored,
            id,
            profile_index,
            &row_boundary_locations,
        )?);
        let required_scopes = match profile.get("requiredScopes") {
            None | Some(Value::Null) => &[][..],
            Some(Value::Array(scopes)) => scopes.as_slice(),
            Some(_) => bail!("BReg access profile {id} requiredScopes must be an array"),
        };
        for scope in required_scopes {
            scopes.insert(
                scope
                    .as_str()
                    .with_context(|| {
                        format!("BReg access profile {id} requiredScopes must be strings")
                    })?
                    .to_owned(),
            );
        }
        let required_purposes = match profile.get("requiredPurposes") {
            None | Some(Value::Null) => &[][..],
            Some(Value::Array(purposes)) => purposes.as_slice(),
            Some(_) => bail!("BReg access profile {id} requiredPurposes must be an array"),
        };
        if !required_purposes.is_empty() {
            let profile_purposes = required_purposes
                .iter()
                .map(|purpose| {
                    purpose.as_str().map(str::to_owned).with_context(|| {
                        format!("BReg access profile {id} requiredPurposes must be strings")
                    })
                })
                .collect::<Result<BTreeSet<_>>>()?;
            allowed_purposes = Some(match allowed_purposes {
                None => profile_purposes,
                Some(existing) => existing.intersection(&profile_purposes).cloned().collect(),
            });
        }
    }
    let purpose = allowed_purposes
        .map(|purposes| {
            purposes.into_iter().next().with_context(|| {
                format!(
                    "the selected request's review and apply access profiles disagree on {PURPOSE_CLAIM}"
                )
            })
        })
        .transpose()?;
    Ok(ReviewerAuthority {
        profiles: profile_ids.into_iter().map(str::to_owned).collect(),
        scopes,
        purpose,
        row_boundary_findings,
        warnings,
    })
}

/// One row boundary found nested under a BReg access profile, paired with
/// the JSON Pointer segments (relative to the profile itself) that reach its
/// enclosing `rowBoundaries` array, and the entity it constrains: the entity
/// named by the permission, apply target, action target, or request
/// presence binding the boundary is nested under.
struct RowBoundaryLocation {
    pointer: String,
    entity: Option<String>,
    field: String,
    claim: String,
    operator: Option<String>,
}

/// Locates every row boundary nested under a BReg access profile (directly
/// under a `permissions[]` entry, or nested deeper under a permission's
/// `applyTargets[]`, `targets[]`, or `requestPresence[]`). `entity` is the
/// ambient entity carried down from the nearest enclosing object that names
/// one with an `entity` or `requestType` string field; `path` is the
/// traversal's working stack of segments and is empty again on return.
fn collect_row_boundary_locations(
    value: &Value,
    entity: Option<&str>,
    path: &mut Vec<String>,
    locations: &mut Vec<RowBoundaryLocation>,
) {
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                path.push(index.to_string());
                collect_row_boundary_locations(value, entity, path, locations);
                path.pop();
            }
        }
        Value::Object(values) => {
            let scoped_entity = values
                .get("entity")
                .and_then(Value::as_str)
                .or_else(|| values.get("requestType").and_then(Value::as_str))
                .or(entity);
            for (key, value) in values {
                path.push(key.clone());
                if key == "rowBoundaries" {
                    for boundary in value.as_array().into_iter().flatten() {
                        if let Some(claim) = boundary["claim"].as_str() {
                            locations.push(RowBoundaryLocation {
                                pointer: path.join("/"),
                                entity: scoped_entity.map(str::to_owned),
                                field: boundary["field"].as_str().unwrap_or_default().to_owned(),
                                claim: claim.to_owned(),
                                operator: boundary["operator"].as_str().map(str::to_owned),
                            });
                        }
                    }
                } else {
                    collect_row_boundary_locations(value, scoped_entity, path, locations);
                }
                path.pop();
            }
        }
        _ => {}
    }
}

/// BReg field types whose row boundary claim BReg's runtime reads with
/// `.as_str()` (`registry-breg`'s `auth.rs` `mapped_scalar_claim`), the same
/// shape a local Casework dev-client claim uses. A `boolean` field reads its
/// claim with `.as_bool()` and an `int64` field with `.as_i64()`, and
/// `crs84-point` and `structured` fields cannot be row-boundary fields at
/// all: none of those can be represented by a local dev-client claim.
const STRING_SHAPED_ROW_BOUNDARY_FIELD_TYPES: &[&str] = &[
    "string",
    "text",
    "decimal",
    "date",
    "timestamp",
    "uuid",
    "reference",
    "vocabulary-code",
];

/// The authored `type` tag of `field` on `entity`, read from the raw
/// registry.yaml JSON the same way BReg's compiler resolves it, or `None`
/// when the entity or field cannot be found there. `source add` always runs
/// `bregctl check` first, so a registry.yaml naming an entity or field that
/// does not exist is already refused before this is reached; this stays
/// `Option` rather than panicking so an unexpected shape here is treated as
/// unresolved, and so refused conservatively, rather than crashing.
fn resolve_row_boundary_field_type(authored: &Value, entity: &str, field: &str) -> Option<String> {
    if field == "id" {
        // The canonical id field is always an implicit Uuid; it carries no
        // authored `type` tag of its own for a lookup below to find.
        return Some("uuid".to_owned());
    }
    authored["entities"]
        .as_array()?
        .iter()
        .find(|candidate| candidate["id"] == entity)?
        .get("fields")?
        .as_array()?
        .iter()
        .find(|candidate| candidate["id"] == field)?
        .get("type")?
        .as_str()
        .map(str::to_owned)
}

/// Groups every row boundary location representable by a local dev-client
/// claim into one finding per `rowBoundaries` array, and refuses the
/// pairing outright for any location the local claim model cannot carry.
/// BReg's runtime reads an `equals` row boundary claim as the field's own
/// scalar shape and an `in` claim as a JSON array of that shape, but a local
/// Casework dev-client claim (`human_dev_client`) is always a plain string,
/// so only `equals` over a string-shaped field can be added to one by hand.
fn represent_row_boundary_locations(
    authored: &Value,
    id: &str,
    profile_index: usize,
    locations: &[RowBoundaryLocation],
) -> Result<Vec<Value>> {
    let mut claims_by_pointer: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for location in locations {
        let field_type = location
            .entity
            .as_deref()
            .and_then(|entity| resolve_row_boundary_field_type(authored, entity, &location.field));
        let representable = location.operator.as_deref() == Some("equals")
            && field_type.as_deref().is_some_and(|field_type| {
                STRING_SHAPED_ROW_BOUNDARY_FIELD_TYPES.contains(&field_type)
            });
        if !representable {
            bail!(
                "BReg access profile {id} row boundary claim {claim} uses operator `{operator}` against a `{field_type}` field; the local Casework dev-client claim model holds only strings, so only operator `equals` over a string-shaped field can be added to a local reviewer client by hand",
                claim = location.claim,
                operator = location.operator.as_deref().unwrap_or("<none>"),
                field_type = field_type.as_deref().unwrap_or("<unresolved>"),
            );
        }
        claims_by_pointer
            .entry(location.pointer.as_str())
            .or_default()
            .insert(location.claim.clone());
    }
    Ok(claims_by_pointer
        .into_iter()
        .map(|(pointer, claims)| row_boundary_finding(id, profile_index, pointer, &claims))
        .collect())
}

/// A finding warning that a BReg access profile's rowBoundaries claims are
/// not reflected in the local dev-client export: BReg's runtime still
/// refuses that profile for a local reviewer client whose token lacks the
/// claim, so access is neither widened nor silently bypassed, but an
/// operator who wants a local reviewer to exercise the profile must add the
/// claim to that client by hand. Only reached for an `equals` row boundary
/// over a string-shaped field; `represent_row_boundary_locations` refuses
/// every other operator or field type instead, since none of those can be
/// represented by a local dev-client claim.
fn row_boundary_finding(
    id: &str,
    profile_index: usize,
    pointer: &str,
    claims: &BTreeSet<String>,
) -> Value {
    let claim_list = claims.iter().cloned().collect::<Vec<_>>().join(", ");
    json!({
        "severity": "finding",
        "code": "casework.source-add.row-boundary-claim-unsupported",
        "artifact": "breg_access_profile",
        "path": format!("registry.yaml:/accessProfiles/{profile_index}/{pointer}"),
        "message": format!(
            "BReg access profile {id} uses rowBoundaries on claim(s) {claim_list}; the local dev-client export does not add these claims, so a local Casework reviewer client cannot exercise the profile until an operator adds them by hand, each set to the string value equal to the field's stored value"
        ),
        "suggestedAction": format!(
            "Add claim(s) {claim_list} to the local Casework reviewer dev clients that need access profile {id}, each set to the string value BReg's rowBoundaries operator equals expects for the matching field."
        ),
    })
}

/// The BReg dev client bound to one Casework dev client: same id, scopes, and
/// claims, plus an explicit service actor kind for the requester. It has no
/// access profile of its own. A staff or supervisor client
/// additionally carries the selected request's reviewer scopes, maps its
/// Casework principal into the BReg reviewer claim, and carries any required
/// purpose claim. Only those reviewer roles explicitly opt in to BReg's
/// `allowedClients` list.
fn human_dev_client(
    client: &Value,
    role: &str,
    casework_principal_claim: &str,
    authority: Option<&ReviewerAuthority>,
) -> Result<Value> {
    let id = client["id"]
        .as_str()
        .context("a Casework dev client's id must be a string")?;
    let mut scopes: BTreeSet<String> = client["scopes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    // Every local dev-client claim is a plain string: BReg's runtime accepts
    // a JSON array for an `in` row boundary and a JSON bool or number for a
    // Boolean or Int64 field, neither of which this map can hold. See
    // `represent_row_boundary_locations`, which refuses those pairings
    // instead of reporting a finding no local claim could ever satisfy.
    let mut claims: BTreeMap<String, String> = client["claims"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
        .collect();
    if role == "requester" {
        claims.insert(ACTOR_KIND_CLAIM.to_owned(), SERVICE_ACTOR_KIND.to_owned());
    }
    let allow_breg_access = matches!(role, "staff" | "supervisor");
    if allow_breg_access {
        let authority = authority.context(
            "a Casework staff or supervisor dev client has no reviewer authority to bind",
        )?;
        let principal = if casework_principal_claim == "sub" {
            bail!("Casework dev client {id} uses principalClaim sub, whose stock-issuer subject is session-qualified; author an explicit stable principal claim for the shared BREG issuer bridge")
        } else {
            claims
                .get(casework_principal_claim)
                .cloned()
                .with_context(|| {
                    format!(
                        "Casework dev client {id} has no string value for its configured principal claim"
                    )
                })?
        };
        match claims.get(READER_PRINCIPAL_CLAIM) {
            Some(existing) if existing != &principal => bail!(
                "Casework dev client {id} sets a BReg reviewer principal that conflicts with its configured Casework principal"
            ),
            _ => {
                claims.insert(READER_PRINCIPAL_CLAIM.to_owned(), principal);
            }
        }
        scopes.extend(authority.scopes.iter().cloned());
        if let Some(purpose) = &authority.purpose {
            match claims.get(PURPOSE_CLAIM) {
                Some(existing) if existing != purpose => bail!(
                    "Casework dev client {id} already sets {PURPOSE_CLAIM} to a value that conflicts with the selected BReg request's reviewer purpose"
                ),
                _ => {
                    claims.insert(PURPOSE_CLAIM.to_owned(), purpose.clone());
                }
            }
        }
    }
    if scopes.len() > MAX_BREG_DEV_CLIENT_SCOPES || claims.len() > MAX_BREG_DEV_CLIENT_CLAIMS {
        bail!(
            "Casework dev client {id} exceeds BReg local client scope or claim bounds after reviewer authority is added"
        );
    }
    let access_profiles = if role == "supervisor" {
        authority
            .map(|authority| authority.profiles.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut result = json!({
        "id": id,
        "accessProfiles": access_profiles,
        "scopes": scopes.into_iter().collect::<Vec<_>>(),
        "claims": claims,
    });
    if allow_breg_access {
        result["allowBregAccess"] = json!(true);
    }
    if result["claims"]["registry_actor_kind"] == "human" {
        result["allowHumanFixture"] = json!(true);
    }
    Ok(result)
}

/// Plans the BReg `dev-clients.yaml` side of `source add`: the reader client
/// exercising casework-reader, and one client for every Casework dev client.
/// Requesters need the borrowed issuer but receive no BReg access profile.
/// Reads but never writes; the caller decides whether and when to apply
/// `write`. A deployment project with either local clients file absent skips
/// this auxiliary local-development patch.
fn plan_breg_dev_clients(
    registry: &Path,
    project: &Path,
    authored: &Value,
    requests: &[SelectedRequest<'_>],
) -> Result<DevClientsPlan> {
    let casework_dev_clients_path = project.join("dev-clients.yaml");
    let dev_clients_path = registry.join("dev-clients.yaml");
    let bytes = match fs::read(&casework_dev_clients_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(absent_dev_clients_plan())
        }
        Err(error) => return Err(error).context("reading the Casework project's dev-clients.yaml"),
        Ok(bytes) => bytes,
    };
    match fs::metadata(&dev_clients_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(absent_dev_clients_plan())
        }
        Err(error) => return Err(error).context("reading BReg dev-clients.yaml"),
        Ok(_) => {}
    }
    let casework_dev_clients: Value = serde_norway::from_slice(&bytes)
        .context("parsing the Casework project's dev-clients.yaml")?;
    let casework_policy = load_casework_policy(project)?;
    let profiles = casework_policy["accessProfiles"]
        .as_array()
        .context("casework.yaml has no accessProfiles")?;
    let casework_clients = casework_dev_clients["clients"]
        .as_array()
        .context("the Casework project's dev-clients.yaml has no clients")?;

    let mut eligible = Vec::new();
    let mut needs_authority = false;
    let mut reviewer_clients = BTreeSet::new();
    let producer_profiles = requests
        .iter()
        .map(|request| request.producer_profile.as_str())
        .collect::<BTreeSet<_>>();
    let mut producer_clients = BTreeMap::new();
    for client in casework_clients {
        let profile_id = client["accessProfile"]
            .as_str()
            .context("a Casework dev client's accessProfile must be a string")?;
        let profile = profiles
            .iter()
            .find(|profile| profile["id"] == profile_id)
            .context("a Casework dev client names an access profile absent from casework.yaml")?;
        let role = profile["role"]
            .as_str()
            .context("a Casework access profile's role must be a string")?;
        let principal_claim = profile["principalClaim"]
            .as_str()
            .context("a Casework access profile's principalClaim must be a string")?;
        if matches!(role, "staff" | "supervisor") {
            needs_authority = true;
            reviewer_clients.insert(
                client["id"]
                    .as_str()
                    .context("a Casework dev client's id must be a string")?
                    .to_owned(),
            );
        }
        if producer_profiles.contains(profile_id) {
            producer_clients.insert(
                profile_id,
                client["id"]
                    .as_str()
                    .context("the Casework producer dev client's id must be a string")?
                    .to_owned(),
            );
        }
        eligible.push((client, role.to_owned(), principal_claim.to_owned()));
    }
    // One Casework reviewer acts on every paired request entity, so its BReg
    // client carries the authority of every review and apply grant together.
    let paired = json!({
        "reviewPermissions": requests
            .iter()
            .flat_map(|request| request.metadata["reviewPermissions"].as_array().into_iter().flatten())
            .collect::<Vec<_>>(),
        "applyPermissions": requests
            .iter()
            .flat_map(|request| request.metadata["applyPermissions"].as_array().into_iter().flatten())
            .collect::<Vec<_>>(),
    });
    let authority = if needs_authority {
        Some(reviewer_authority(authored, &paired, &reviewer_clients)?)
    } else {
        None
    };
    let findings = authority
        .as_ref()
        .map(|authority| authority.row_boundary_findings.clone())
        .unwrap_or_default();
    let mut clients = vec![reader_dev_client()];
    for (client, role, principal_claim) in &eligible {
        clients.push(human_dev_client(
            client,
            role,
            principal_claim,
            authority.as_ref(),
        )?);
    }
    let mut local_review_authorities = BTreeMap::new();
    for request in requests {
        let producer_client = producer_clients
            .get(request.producer_profile.as_str())
            .context(
                "the Casework project's dev-clients.yaml must bind the admitted producer profile",
            )?;
        let local_review_authority = json!({
            "endpoint":"http://127.0.0.1:8092",
            "profile":request.producer_profile,
            "producerId":request.producer_id,
            "recoveryDays":request.recovery_days,
            "client":producer_client,
        });
        match local_review_authorities.get(&request.authority) {
            Some(existing) if existing != &local_review_authority => bail!(
                "requests sharing review authority {} disagree on its producer admission",
                request.authority
            ),
            Some(_) => {}
            None => {
                local_review_authorities.insert(request.authority.clone(), local_review_authority);
            }
        }
    }

    match fs::read(&dev_clients_path) {
        Ok(original) => {
            let mut authored_dev_clients: Value =
                serde_norway::from_slice(&original).context("parsing BReg dev-clients.yaml")?;
            let mut changes = apply_dev_clients_candidate(&mut authored_dev_clients, &clients)?;
            for (authority_id, authority) in &local_review_authorities {
                apply_local_review_authority_candidate(
                    &mut authored_dev_clients,
                    authority_id,
                    authority,
                    &mut changes,
                )?;
            }
            let proposed = render_dev_clients_preserving_authored_text(
                &original,
                &clients,
                &local_review_authorities,
                &authored_dev_clients,
            )?;
            Ok(DevClientsPlan {
                patch: Value::Array(clients),
                changes,
                warnings: authority
                    .map(|authority| authority.warnings)
                    .unwrap_or_default(),
                write: Some(DevClientsWrite {
                    path: dev_clients_path,
                    original,
                    proposed,
                }),
                findings,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DevClientsPlan {
            findings,
            ..absent_dev_clients_plan()
        }),
        Err(error) => Err(error).context("reading BReg dev-clients.yaml"),
    }
}

fn apply_local_review_authority_candidate(
    root: &mut Value,
    authority_id: &str,
    authority: &Value,
    changes: &mut Value,
) -> Result<()> {
    let authorities = root
        .as_object_mut()
        .context("BReg dev-clients.yaml must contain an object")?
        .entry("reviewAuthorities")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("BReg dev-clients.yaml reviewAuthorities must be an object")?;
    match authorities.get(authority_id) {
        Some(existing) if existing != authority => {
            bail!(
                "BReg local review authority {authority_id} already exists with different content"
            )
        }
        None => {
            authorities.insert(authority_id.to_owned(), authority.clone());
        }
        _ => {}
    }
    changes
        .as_array_mut()
        .expect("dev-client changes are an array")
        .push(json!({"file":"dev-clients.yaml","path":format!("/reviewAuthorities/{authority_id}"),"operation":"ensure_exact"}));
    Ok(())
}

fn absent_dev_clients_plan() -> DevClientsPlan {
    DevClientsPlan {
        patch: json!("absent"),
        changes: json!([]),
        write: None,
        findings: Vec::new(),
        warnings: Vec::new(),
    }
}

fn apply_dev_clients_candidate(root: &mut Value, clients: &[Value]) -> Result<Value> {
    let object = root
        .as_object_mut()
        .context("BReg dev-clients.yaml must contain an object")?;
    let existing = object
        .entry("clients")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("BReg dev-clients.yaml clients must be an array")?;
    let mut changes = Vec::new();
    for client in clients {
        let id = client["id"]
            .as_str()
            .expect("planned BReg dev client has an id");
        match existing.iter().find(|item| item["id"] == id) {
            Some(found) if found != client => {
                bail!("BReg dev client {id} already exists with different content")
            }
            None => existing.push(client.clone()),
            _ => {}
        }
        changes.push(json!({"file":"dev-clients.yaml","path":format!("/clients/{id}"),"operation":"ensure_exact"}));
    }
    if existing.len() > MAX_BREG_DEV_CLIENTS {
        bail!("merged BReg dev-clients.yaml exceeds the local clients v1 32-client bound");
    }
    let mut bound_profiles = BTreeSet::new();
    for client in existing {
        let profiles = client["accessProfiles"]
            .as_array()
            .context("each BReg dev client must declare accessProfiles as an array")?;
        for profile in profiles {
            let profile = profile
                .as_str()
                .context("each BReg dev client access profile must be a string")?;
            if !bound_profiles.insert(profile) {
                bail!("BReg access profile {profile} is bound to more than one local client");
            }
        }
    }
    Ok(Value::Array(changes))
}

fn render_dev_clients_preserving_authored_text(
    original: &[u8],
    clients: &[Value],
    authorities: &BTreeMap<String, Value>,
    expected: &Value,
) -> Result<String> {
    let text = std::str::from_utf8(original).context("BReg dev-clients.yaml must be UTF-8")?;
    if text.trim_start().starts_with('{') {
        // JSON authoring has no comment syntax. Pretty-printing this branch keeps
        // every parsed key while avoiding a misleading claim about preserving
        // comments that JSON cannot contain.
        let mut rendered = serde_json::to_string_pretty(expected)?;
        rendered.push('\n');
        return Ok(rendered);
    }
    let parsed: Value = serde_norway::from_str(text)?;
    let present = parsed["clients"].as_array().cloned().unwrap_or_default();
    let missing: Vec<&Value> = clients
        .iter()
        .filter(|client| !present.iter().any(|item| item["id"] == client["id"]))
        .collect();
    let mut rendered = text.to_owned();
    if !missing.is_empty() {
        rendered = insert_dev_clients(&rendered, &missing)?;
    }
    for (authority_id, authority) in authorities {
        let parsed_so_far: Value = serde_norway::from_str(&rendered)?;
        if parsed_so_far["reviewAuthorities"]
            .get(authority_id)
            .is_none()
        {
            if parsed_so_far.get("reviewAuthorities").is_some() {
                rendered = insert_local_review_authority(&rendered, authority_id, authority)?;
            } else {
                if !rendered.ends_with('\n') {
                    rendered.push('\n');
                }
                rendered.push_str(&render_local_review_authority_yaml(
                    authority_id,
                    authority,
                )?);
            }
        }
    }
    let round_trip: Value =
        serde_norway::from_str(&rendered).context("parsing narrow BReg dev-clients YAML patch")?;
    if &round_trip != expected {
        bail!("narrow BReg dev-clients YAML patch changed unexpected authored content; no files were written");
    }
    Ok(rendered)
}

fn render_local_review_authority_yaml(authority_id: &str, authority: &Value) -> Result<String> {
    Ok(format!(
        "reviewAuthorities:\n{}",
        render_local_review_authority_entry_yaml(authority_id, authority)?
    ))
}

fn render_local_review_authority_entry_yaml(
    authority_id: &str,
    authority: &Value,
) -> Result<String> {
    let object = authority
        .as_object()
        .context("planned local review authority must be an object")?;
    Ok(format!(
        "  {}:\n    endpoint: {}\n    profile: {}\n    producerId: {}\n    recoveryDays: {}\n    client: {}\n",
        yaml_string(authority_id),
        yaml_string(object["endpoint"].as_str().context("authority endpoint is missing")?),
        yaml_string(object["profile"].as_str().context("authority profile is missing")?),
        yaml_string(object["producerId"].as_str().context("authority producerId is missing")?),
        object["recoveryDays"]
            .as_u64()
            .context("authority recoveryDays is missing")?,
        yaml_string(object["client"].as_str().context("authority client is missing")?),
    ))
}

fn insert_local_review_authority(
    text: &str,
    authority_id: &str,
    authority: &Value,
) -> Result<String> {
    let block = render_local_review_authority_entry_yaml(authority_id, authority)?;
    insert_yaml_collection_items(text, "reviewAuthorities", "{}", &block)
}

fn insert_dev_clients(text: &str, clients: &[&Value]) -> Result<String> {
    let mut block = String::new();
    for client in clients {
        block.push_str(&render_dev_client_yaml_block(client)?);
    }
    insert_yaml_collection_items(text, "clients", "[]", &block)
}

fn render_dev_client_yaml_block(client: &Value) -> Result<String> {
    let id = client["id"]
        .as_str()
        .context("planned BReg dev client id must be a string")?;
    let access_profiles = string_array(
        &client["accessProfiles"],
        "planned BReg dev client accessProfiles",
    )?;
    let scopes = string_array(&client["scopes"], "planned BReg dev client scopes")?;
    let claims = client["claims"]
        .as_object()
        .context("planned BReg dev client claims must be an object")?;
    let mut block = format!(
        "  - id: {}\n    accessProfiles: {}\n    scopes: {}\n",
        yaml_string(id),
        flow_sequence(&access_profiles),
        flow_sequence(&scopes),
    );
    if let Some(allow_breg_access) = client.get("allowBregAccess") {
        let allow_breg_access = allow_breg_access
            .as_bool()
            .context("planned BReg dev client allowBregAccess must be a boolean")?;
        block.push_str(&format!("    allowBregAccess: {allow_breg_access}\n"));
    }
    if let Some(allow_human_fixture) = client.get("allowHumanFixture") {
        let allow_human_fixture = allow_human_fixture
            .as_bool()
            .context("planned BReg dev client allowHumanFixture must be a boolean")?;
        block.push_str(&format!("    allowHumanFixture: {allow_human_fixture}\n"));
    }
    if claims.is_empty() {
        block.push_str("    claims: {}\n");
    } else {
        block.push_str("    claims:\n");
        for (key, value) in claims {
            let value = value
                .as_str()
                .context("planned BReg dev client claim values must be strings")?;
            block.push_str(&format!(
                "      {}: {}\n",
                yaml_string(key),
                yaml_string(value)
            ));
        }
    }
    Ok(block)
}

fn string_array<'a>(value: &'a Value, label: &str) -> Result<Vec<&'a str>> {
    value
        .as_array()
        .with_context(|| format!("{label} must be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .with_context(|| format!("{label} entries must be strings"))
        })
        .collect()
}

fn flow_sequence(items: &[&str]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|item| yaml_string(item))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// JSON string syntax is a valid YAML double-quoted scalar syntax and covers
/// commas, colons, comment markers, escapes, and values YAML would otherwise
/// resolve as booleans or numbers.
fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

fn source_description(
    source_id: &str,
    requests: &[SelectedRequest<'_>],
    report: &Value,
) -> Result<Value> {
    let mut description = json!({
        "apiVersion":"registry.registrystack.org/casework-source-description/v1alpha1",
        "kind":"BRegCaseworkSourceDescription",
        "sourceId":source_id,
        "authority":"none",
        "origin":"bregctl explain change-requests",
        "sourceRevision":report["revision"],
    });
    match requests {
        [request] => description["request"] = request.metadata.clone(),
        _ => {
            description["apiVersion"] =
                json!("registry.registrystack.org/casework-source-description/v1alpha2");
            description["requests"] = requests
                .iter()
                .map(|request| request.metadata.clone())
                .collect();
        }
    }
    Ok(description)
}

/// Whether two requests naming one review authority agree on everything the
/// authority's binding entry carries.
fn same_review_admission(left: &SelectedRequest<'_>, right: &SelectedRequest<'_>) -> bool {
    let completion = |request: &SelectedRequest<'_>| {
        request.completion.as_ref().map(|completion| {
            (
                completion.destination_id.clone(),
                completion.recipient_binding.clone(),
            )
        })
    };
    left.producer_profile == right.producer_profile
        && left.producer_id == right.producer_id
        && left.recovery_days == right.recovery_days
        && completion(left) == completion(right)
}

fn runtime_binding(
    source_id: &str,
    registry_id: &str,
    requests: &[SelectedRequest<'_>],
) -> Result<String> {
    let mut authorities: BTreeMap<&str, &SelectedRequest<'_>> = BTreeMap::new();
    let mut executors: BTreeMap<&str, &str> = BTreeMap::new();
    for request in requests {
        match authorities.get(request.authority.as_str()) {
            Some(existing) if !same_review_admission(existing, request) => bail!(
                "requests sharing review authority {} disagree on its producer admission",
                request.authority
            ),
            Some(_) => {}
            None => {
                authorities.insert(&request.authority, request);
            }
        }
        if let ApplicationPlan::Automatic {
            executor,
            access_profile,
        } = &request.application
        {
            match executors.get(executor.as_str()) {
                Some(existing) if existing != access_profile => bail!(
                    "requests sharing review executor {executor} disagree on its access profile"
                ),
                Some(_) => {}
                None => {
                    executors.insert(executor, access_profile);
                }
            }
        }
    }
    let mut binding = format!(
        "# Candidate BReg operator binding. Review the endpoints and secret references, then merge this into launcher-owned runtime config.\neventDestinations:\n  casework:\n    origin: http://localhost:8100\n    path: /events/sources/{source_id}\n    networkProfile: loopbackDevelopmentHttp\n    dnsFamily: ipv4Only\n    allowedPrivateCidrs: []\n    hmacSha256KeyRef: secret:file/breg-casework-webhook\n    classificationCeiling: restricted\n    deliveryCeilings:\n      attemptTimeoutMilliseconds: 5000\n      maximumAttempts: 5\nreviewAuthorities:\n"
    );
    for (authority, request) in &authorities {
        binding.push_str(&format!(
        "  {}:\n    endpoint: https://casework.example.test\n    profile: {}\n    producerId: {}\n    recoveryDays: {}\n    privateKeyJwt:\n      tokenEndpoint: https://identity.example.test/oauth2/token\n      clientIdRef: secret:file/casework-producer-client-id\n      clientAssertionKeyRef: secret:file/casework-producer-private-jwk\n      assertionAudience: https://identity.example.test\n      resource: https://casework.example.test\n      scopes: [casework:reviews:request]\n",
            yaml_string(authority),
            yaml_string(&request.producer_profile),
            yaml_string(&request.producer_id),
            request.recovery_days,
        ));
        if let Some(completion) = &request.completion {
            binding.push_str(&format!(
                "    completionTokenRef: secret:file/casework-completion-token\n    completionRecipient: {}\n",
                yaml_string(&completion.recipient_binding)
            ));
        }
    }
    if !executors.is_empty() {
        binding.push_str("reviewExecutors:\n");
    }
    for (executor, access_profile) in &executors {
        binding.push_str(&format!(
            "  {}:\n    endpoint: https://registry.example.test\n    tokenRef: secret:file/casework-automatic-executor-token\n    registryId: {}\n    accessProfile: {}\n",
            yaml_string(executor),
            yaml_string(registry_id),
            yaml_string(access_profile),
        ));
    }
    serde_norway::from_str::<Value>(&binding)
        .context("validating generated BReg runtime binding")?;
    Ok(binding)
}

fn verify_candidate(binary: &Path, registry: &Path, proposed: &str) -> Result<Value> {
    let staging = tempfile::Builder::new()
        .prefix(".casework-breg-candidate-")
        .tempdir_in(registry.parent().context("BReg project has no parent")?)
        .context("creating BReg candidate staging beside the authored project")?;
    copy_tree(registry, staging.path(), registry)?;
    fs::write(staging.path().join("registry.yaml"), proposed)
        .context("staging BReg candidate registry.yaml")?;
    let report = invoke(binary, &["--format", "json", "check"], staging.path())?;
    require_ok("candidate check", &report)?;
    let explanation = invoke(
        binary,
        &["--format", "json", "explain", "change-requests"],
        staging.path(),
    )?;
    require_ok("candidate explain change-requests", &explanation)?;
    Ok(explanation)
}

fn copy_tree(source: &Path, destination: &Path, root: &Path) -> Result<()> {
    for entry in fs::read_dir(source).context("reading BReg project for candidate staging")? {
        let entry = entry?;
        // Neither path is an authored BReg input. In particular, .breg
        // can contain live control sockets that cannot be copied as files.
        if source == root && matches!(entry.file_name().to_str(), Some(".breg" | ".git")) {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            bail!("BReg candidate staging refuses symlinks");
        }
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            fs::create_dir(&target)?;
            copy_tree(&entry.path(), &target, root)?;
        } else if kind.is_file() {
            let metadata = entry.metadata()?;
            if metadata.len() > MAX_PROVIDER_OUTPUT as u64 {
                bail!("BReg project file exceeds candidate staging limit");
            }
            fs::copy(entry.path(), target)?;
        } else {
            bail!(
                "BReg candidate staging accepts only regular files and directories under {}",
                root.display()
            );
        }
    }
    Ok(())
}

fn write_json_atomic(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_atomic(path, &bytes)
}

fn require_absent_or_exact_json(path: &Path, expected: &Value) -> Result<()> {
    match fs::read(path) {
        Ok(bytes) => {
            let actual: Value = serde_json::from_slice(&bytes)
                .with_context(|| format!("existing {} is not valid JSON", path.display()))?;
            if &actual != expected {
                bail!(
                    "existing {} has different authored content; it was preserved",
                    path.display()
                );
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn require_absent_or_exact(path: &Path, expected: &[u8]) -> Result<()> {
    match fs::read(path) {
        Ok(actual) if actual == expected => Ok(()),
        Ok(_) => bail!(
            "existing {} has different authored content; it was preserved",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output has no parent")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("creating same-directory output")?;
    use std::io::Write as _;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("publishing output atomically")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_source_description(project: &Path, description: &str) {
        let policy_path = project.join("casework.yaml");
        let mut policy: Value = serde_norway::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
        policy["sources"][0]["description"] = json!(description);
        fs::write(&policy_path, serde_norway::to_string(&policy).unwrap()).unwrap();
    }

    #[test]
    fn source_import_uses_the_declared_description_path() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        set_source_description(&project, "imports/professional.json");

        assert_eq!(
            configured_source_description_path(&project, "professional-licences").unwrap(),
            project.join("imports/professional.json")
        );
    }

    #[test]
    fn source_import_refuses_paths_outside_the_project() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        set_source_description(&project, "../professional.json");

        let error = configured_source_description_path(&project, "professional-licences")
            .expect_err("a source import cannot leave its project");
        assert!(format!("{error:#}").contains("normalized path inside the project"));
    }

    #[test]
    fn source_import_refuses_symlinked_path_components() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, project.join("imports")).unwrap();
        set_source_description(&project, "imports/professional.json");

        let error = configured_source_description_path(&project, "professional-licences")
            .expect_err("a source import cannot traverse a symlink");
        assert!(format!("{error:#}").contains("must not contain symlinks"));
    }

    #[test]
    fn source_apply_refuses_description_and_binding_path_collision() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        set_source_description(&project, "sources/professional-licences.breg-runtime.yaml");
        let project = fs::canonicalize(project).unwrap();
        let description =
            configured_source_description_path(&project, "professional-licences").unwrap();
        let binding = project.join("sources/professional-licences.breg-runtime.yaml");

        let error = require_distinct_output_paths(&description, &binding)
            .expect_err("source outputs must not alias each other");

        assert!(format!("{error:#}").contains("must not be the BReg runtime binding path"));
        assert!(!binding.exists());
    }

    #[test]
    fn source_apply_prepares_a_missing_runtime_binding_directory() {
        let root = tempfile::tempdir().unwrap();
        let project = fs::canonicalize(root.path()).unwrap();
        let binding = project.join("sources/professional.breg-runtime.yaml");

        ensure_runtime_binding_parent(&project, &binding).unwrap();

        assert!(project.join("sources").is_dir());
        write_atomic(&binding, b"eventDestinations: {}\n").unwrap();
        assert_eq!(fs::read(binding).unwrap(), b"eventDestinations: {}\n");
    }

    #[test]
    fn source_apply_refuses_a_symlinked_runtime_binding_directory() {
        let root = tempfile::tempdir().unwrap();
        let project = fs::canonicalize(root.path()).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), project.join("sources")).unwrap();
        let binding = project.join("sources/professional.breg-runtime.yaml");

        let error = ensure_runtime_binding_parent(&project, &binding)
            .expect_err("a runtime binding must not traverse a symlink");

        assert!(format!("{error:#}").contains("must not be a symlink"));
        assert!(!outside
            .path()
            .join("professional.breg-runtime.yaml")
            .exists());
    }

    #[test]
    fn source_import_connects_the_breg_request_to_one_casework_producer() {
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join("casework.yaml"), serde_json::to_vec(&json!({
            "sources": [{"id":"professional", "adapter":"breg", "requests":[{"entity":"correction"}]}],
            "reviewKinds":[{"id":"registry-correction", "purpose":"approval", "contextStrategy":"source"}],
            "reviewProducers":[{
                "id":"registry-breg", "profile":"integration-requester", "recoveryDays":7,
                "sourceNamespaces":["professional-licences"], "kinds":["registry-correction"]
            }]
        })).unwrap()).unwrap();
        let report = json!({"explanation":{"requests":[{
            "requestEntity":"correction",
            "review":{"authority":"casework-main","policyId":"registry-correction"},
            "onApproved":{"mode":"manual"}
        }]}});
        let selected = select_requests(
            project.path(),
            "professional",
            "professional-licences",
            &report,
        )
        .unwrap();
        let [selected] = selected.as_slice() else {
            panic!("one declared request entity selects one request");
        };
        assert_eq!(selected.authority, "casework-main");
        assert_eq!(selected.policy_id, "registry-correction");
        assert_eq!(selected.producer_id, "registry-breg");
        assert!(matches!(selected.application, ApplicationPlan::Manual));

        assert!(
            select_requests(project.path(), "professional", "another-registry", &report).is_err()
        );
    }

    fn casework_policy_with_one_review_kind() -> Value {
        json!({
            "sources": [{"id":"professional", "adapter":"breg", "requests":[{"entity":"correction"}]}],
            "reviewKinds":[{"id":"registry-correction", "purpose":"approval", "contextStrategy":"source"}],
            "reviewProducers":[]
        })
    }

    #[test]
    fn unpaired_casework_review_policies_report_a_finding_when_a_sibling_entity_names_an_undeclared_policy(
    ) {
        let project = tempfile::tempdir().unwrap();
        fs::write(
            project.path().join("casework.yaml"),
            serde_json::to_vec(&casework_policy_with_one_review_kind()).unwrap(),
        )
        .unwrap();
        let authored = json!({"entities":[
            {"id":"correction", "changeRequest":{"review":{"authority":"casework","policyId":"registry-correction"}}},
            {"id":"address-correction", "changeRequest":{"review":{"authority":"casework","policyId":"missing-kind"}}}
        ]});

        let findings =
            check_unpaired_review_policies(project.path(), &authored, "correction", "casework")
                .expect("an unresolvable sibling review policy must not refuse the pairing");

        let [finding] = findings.as_slice() else {
            panic!("expected exactly one finding, got {findings:?}");
        };
        assert_eq!(finding["severity"], "finding");
        let message = finding["message"].as_str().unwrap();
        assert!(message.contains("address-correction"), "{message}");
        assert!(message.contains("missing-kind"), "{message}");
        assert!(
            message.contains("no reviewKinds[].id matching"),
            "{message}"
        );
        assert_eq!(
            finding["path"],
            "registry.yaml:/entities/1/changeRequest/review/policyId"
        );
    }

    #[test]
    fn unpaired_casework_review_policies_leave_a_non_string_sibling_policy_id_to_bregctl_check() {
        let project = tempfile::tempdir().unwrap();
        fs::write(
            project.path().join("casework.yaml"),
            serde_json::to_vec(&casework_policy_with_one_review_kind()).unwrap(),
        )
        .unwrap();
        // `bregctl check` refuses a missing or non-string policyId before this
        // check runs, so it promises no finding for one.
        let authored = json!({"entities":[
            {"id":"correction", "changeRequest":{"review":{"authority":"casework","policyId":"registry-correction"}}},
            {"id":"numeric-policy", "changeRequest":{"review":{"authority":"casework","policyId":123}}},
            {"id":"no-policy", "changeRequest":{"review":{"authority":"casework"}}}
        ]});

        let findings =
            check_unpaired_review_policies(project.path(), &authored, "correction", "casework")
                .expect("a non-string sibling policyId must not refuse the pairing");

        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn unpaired_casework_review_policies_ignore_the_paired_entity_and_other_authorities() {
        let project = tempfile::tempdir().unwrap();
        fs::write(
            project.path().join("casework.yaml"),
            serde_json::to_vec(&casework_policy_with_one_review_kind()).unwrap(),
        )
        .unwrap();
        let authored = json!({"entities":[
            {"id":"correction", "changeRequest":{"review":{"authority":"casework","policyId":"undeclared-but-paired-so-skipped"}}},
            {"id":"external-workflow", "changeRequest":{"review":{"authority":"external-reviewer","policyId":"anything"}}},
            {"id":"plain-dataset"},
            {"id":"sibling-correction", "changeRequest":{"review":{"authority":"casework","policyId":"registry-correction"}}}
        ]});

        let findings =
            check_unpaired_review_policies(project.path(), &authored, "correction", "casework")
                .unwrap();
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn runtime_binding_includes_optional_completion_and_automatic_application() {
        let metadata = json!({"requestEntity":"correction"});
        let request = SelectedRequest {
            metadata: &metadata,
            authority: "casework-main".to_owned(),
            policy_id: "registry-correction".to_owned(),
            producer_id: "registry-breg".to_owned(),
            producer_profile: "integration-requester".to_owned(),
            recovery_days: 7,
            completion: Some(CompletionPlan {
                destination_id: "registry-completion".to_owned(),
                recipient_binding: "breg-main".to_owned(),
            }),
            application: ApplicationPlan::Automatic {
                executor: "registry-automatic".to_owned(),
                access_profile: "automatic-applier".to_owned(),
            },
        };

        let binding = runtime_binding(
            "professional",
            "professional-licences",
            std::slice::from_ref(&request),
        )
        .unwrap();
        let parsed: Value = serde_norway::from_str(&binding).unwrap();
        assert_eq!(
            parsed["reviewAuthorities"]["casework-main"]["completionRecipient"],
            "breg-main"
        );
        assert_eq!(
            parsed["reviewExecutors"]["registry-automatic"]["accessProfile"],
            "automatic-applier"
        );
        assert_eq!(
            parsed["reviewExecutors"]["registry-automatic"]["registryId"],
            "professional-licences"
        );
    }

    #[test]
    fn candidate_adds_only_exact_hook_and_reader() {
        let mut root = json!({"entities":[{"id":"request"}],"accessProfiles":[]});
        apply_breg_candidate(&mut root, "request", &record_reader(&[])).unwrap();
        assert_eq!(
            root["entities"][0]["hooks"][0]["trigger"],
            "request_lifecycle"
        );
        assert_eq!(
            root["accessProfiles"][0]["permissions"][0]["operations"],
            json!(["get", "list"])
        );
        assert_eq!(
            root["accessProfiles"][0]["permissions"][0]["readableRequestFields"],
            json!(["review_state"])
        );
        apply_breg_candidate(&mut root, "request", &record_reader(&[])).unwrap();
        assert_eq!(root["entities"][0]["hooks"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn routing_projection_grants_only_declared_source_fields() {
        let project = tempfile::tempdir().unwrap();
        let write_policy = |projection: Value| {
            fs::write(
                project.path().join("casework.yaml"),
                serde_json::to_vec(&json!({
                    "sources":[{"id":"professional", "requests":[{"entity":"request", "projection":projection}]}]
                }))
                .unwrap(),
            )
            .unwrap();
        };
        let metadata = json!({"fields":[{"field":"region","apiName":"region"}, {"field":"private-note","apiName":"privateNote"}]});
        write_policy(json!(["region"]));
        let projection =
            source_projection(project.path(), "professional", "request", &metadata).unwrap();
        let input = "# keep authored context\nentities:\n  - id: request\n    route: requests\naccessProfiles: [] # keep the profile context\n";
        let mut expected =
            json!({"entities":[{"id":"request","route":"requests"}],"accessProfiles":[]});
        apply_breg_candidate(&mut expected, "request", &record_reader(&projection)).unwrap();
        let rendered = render_candidate_preserving_authored_text(
            input.as_bytes(),
            "request",
            &expected,
            &record_reader(&projection),
        )
        .unwrap();
        assert!(rendered.contains("# keep authored context"));
        assert!(rendered.contains("accessProfiles: # keep the profile context"));
        assert_eq!(
            expected["accessProfiles"][0]["permissions"][0]["readableFields"],
            json!(["record", "region"])
        );
        assert_eq!(
            expected["entities"][0]["hooks"][0]["projection"],
            json!(["record"])
        );
        assert!(!rendered.contains("private-note"));
        write_policy(json!(["unknown"]));
        assert!(source_projection(project.path(), "professional", "request", &metadata).is_err());
        write_policy(json!(["region", "region"]));
        assert!(source_projection(project.path(), "professional", "request", &metadata).is_err());
    }

    fn target(binding: Value) -> Value {
        json!({"target":{"entity":"farmer","binding":binding}})
    }

    /// The reader grant for a request whose target record field is `record`.
    fn record_reader(projection: &[String]) -> ReaderGrant {
        let metadata = json!({"effects":[target(json!({"kind":"existing","fromField":{"field":"record","apiName":"record"}}))]});
        reader_grant(&metadata, projection).unwrap()
    }

    #[test]
    fn reader_grant_reads_the_request_target_field_whatever_its_name() {
        let metadata = json!({
            "effects":[target(json!({"kind":"existing","fromField":{"field":"farmer-ref","apiName":"farmerRef"}}))],
            "planner":{"kind":"declarative"}
        });
        let grant = reader_grant(&metadata, &["region".to_owned()]).unwrap();
        assert_eq!(grant.fields, ["farmer-ref", "region"]);
        assert_eq!(grant.event_field, "farmer-ref");

        let planned = json!({
            "effects":[],
            "planner":{"kind":"rhai","possibleWrites":[{"target":{"kind":"existing","entity":"farmer","fromField":{"field":"farmer-ref","apiName":"farmerRef"}}}]}
        });
        let grant = reader_grant(&planned, &[]).unwrap();
        assert_eq!(grant.fields, ["farmer-ref"]);
        assert_eq!(grant.event_field, "farmer-ref");
    }

    #[test]
    fn reader_grant_for_a_create_request_carries_a_projected_field() {
        let metadata = json!({
            "effects":[target(json!({"kind":"reserved_create","effect":"register"}))],
            "planner":{"kind":"declarative"}
        });
        let grant = reader_grant(&metadata, &["region".to_owned(), "district".to_owned()]).unwrap();
        assert_eq!(grant.fields, ["district", "region"]);
        assert_eq!(grant.event_field, "region");
        let input = "entities:\n  - id: request\n    route: requests\naccessProfiles: []\n";
        let mut expected: Value = serde_norway::from_str(input).unwrap();
        apply_breg_candidate(&mut expected, "request", &grant).unwrap();
        let rendered = render_candidate_preserving_authored_text(
            input.as_bytes(),
            "request",
            &expected,
            &grant,
        )
        .unwrap();
        assert_eq!(
            serde_norway::from_str::<Value>(&rendered).unwrap(),
            expected
        );
        assert_eq!(
            expected["entities"][0]["hooks"][0]["projection"],
            json!(["region"])
        );
        assert!(!rendered.contains("record"));
        let error = reader_grant(&metadata, &[]).err().unwrap();
        assert!(format!("{error:#}").contains("projection"));
    }

    #[test]
    fn candidate_refuses_conflicting_existing_grant() {
        let mut root = json!({"entities":[{"id":"request"}],"accessProfiles":[{"id":"casework-reader","permissions":[]}]});
        assert!(apply_breg_candidate(&mut root, "request", &record_reader(&[])).is_err());
    }

    #[test]
    fn pairing_a_second_request_entity_extends_the_shared_reader_profile() {
        let mut root = json!({"entities":[{"id":"request"},{"id":"transfer"}],"accessProfiles":[]});
        apply_breg_candidate(&mut root, "request", &record_reader(&[])).unwrap();
        let region = record_reader(&["region".to_owned()]);
        apply_breg_candidate(&mut root, "transfer", &region).unwrap();
        let once = root.clone();
        apply_breg_candidate(&mut root, "transfer", &region).unwrap();
        assert_eq!(root, once, "re-pairing an entity changes nothing");
        let profiles = root["accessProfiles"].as_array().unwrap();
        assert_eq!(profiles.len(), 1);
        let entities = profiles[0]["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|permission| permission["entity"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(entities, ["request", "transfer"]);
        assert_eq!(
            profiles[0]["permissions"][1]["readableFields"],
            json!(["record", "region"])
        );

        // Another grant for an entity already paired, or a reader profile of
        // another shape, is still refused.
        assert!(apply_breg_candidate(&mut root.clone(), "request", &region).is_err());
        let mut scoped = once.clone();
        scoped["accessProfiles"][0]["requiredScopes"] = json!(["other"]);
        assert!(apply_breg_candidate(&mut scoped, "request", &record_reader(&[])).is_err());
    }

    #[test]
    fn narrow_yaml_patch_adds_a_permission_to_an_existing_reader_profile() {
        let input = "entities:\n  - id: request\n    route: requests\n  - id: transfer\n    route: transfers\naccessProfiles: []\n";
        let mut first: Value = serde_norway::from_str(input).unwrap();
        apply_breg_candidate(&mut first, "request", &record_reader(&[])).unwrap();
        let paired = render_candidate_preserving_authored_text(
            input.as_bytes(),
            "request",
            &first,
            &record_reader(&[]),
        )
        .unwrap();
        let paired = paired.replace(
            "    permissions:\n",
            "    permissions: # keep the grant context\n",
        );
        let mut second = first.clone();
        apply_breg_candidate(&mut second, "transfer", &record_reader(&[])).unwrap();
        let rendered = render_candidate_preserving_authored_text(
            paired.as_bytes(),
            "transfer",
            &second,
            &record_reader(&[]),
        )
        .unwrap();
        assert!(rendered.contains("# keep the grant context"));
        assert_eq!(serde_norway::from_str::<Value>(&rendered).unwrap(), second);
    }

    #[test]
    fn narrow_yaml_patch_preserves_comments() {
        let input = "# useful\nentities:\n  - id: request\n    route: requests\naccessProfiles:\n  - id: reader\n    # keep this\n    permissions: []\n";
        let mut expected: Value = serde_norway::from_str(input).unwrap();
        apply_breg_candidate(&mut expected, "request", &record_reader(&[])).unwrap();
        let patched = render_candidate_preserving_authored_text(
            input.as_bytes(),
            "request",
            &expected,
            &record_reader(&[]),
        )
        .unwrap();
        assert!(patched.contains("# useful"));
        assert!(patched.contains("# keep this"));
        assert_eq!(serde_norway::from_str::<Value>(&patched).unwrap(), expected);
    }

    /// A synthetic BReg `registry.yaml`'s `accessProfiles` and a selected
    /// request naming a `reviewer` profile in both its review and apply
    /// grants, matching the professional-licences starter's reviewer shape.
    fn reviewer_fixture() -> (Value, Value) {
        let authored = json!({
            "accessProfiles": [{
                "id": "reviewer",
                "principalClaim": "registry_principal",
                "actorKind": "human",
                "requesterClients": ["staff", "supervisor"],
                "requiredScopes": ["starter:reviewer"],
                "requiredPurposes": ["starter-learning"]
            }]
        });
        let request = json!({
            "reviewPermissions": [{"profile": "reviewer"}],
            "applyPermissions": [{"profile": "reviewer"}]
        });
        (authored, request)
    }

    fn selected_request(metadata: &Value) -> SelectedRequest<'_> {
        SelectedRequest {
            metadata,
            authority: "casework".to_owned(),
            policy_id: "scope-correction".to_owned(),
            producer_id: "registry-breg".to_owned(),
            producer_profile: "integration-requester".to_owned(),
            recovery_days: 7,
            completion: None,
            application: ApplicationPlan::Manual,
        }
    }

    fn reviewer_clients() -> BTreeSet<String> {
        ["staff".to_owned(), "supervisor".to_owned()]
            .into_iter()
            .collect()
    }

    #[test]
    fn dev_clients_plan_adds_reader_and_eligible_casework_clients_json_authored() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let registry = tempfile::tempdir().unwrap();
        fs::write(
            registry.path().join("dev-clients.yaml"),
            serde_json::to_vec(&json!({
                "version": 1,
                "clients": [
                    {"id":"operator","accessProfiles":["operator"],"scopes":["starter:operator"],"claims":{}}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        let (authored, request) = reviewer_fixture();
        let plan = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .unwrap();

        let clients = plan.patch.as_array().unwrap();
        let ids: Vec<&str> = clients.iter().map(|c| c["id"].as_str().unwrap()).collect();
        assert_eq!(
            ids,
            [
                "casework-reader",
                "administrator",
                "supervisor",
                "staff",
                "integration-requester"
            ]
        );

        let reader = clients
            .iter()
            .find(|c| c["id"] == "casework-reader")
            .unwrap();
        assert_eq!(reader["accessProfiles"], json!(["casework-reader"]));
        assert_eq!(reader["scopes"], json!(["casework:source-reader"]));
        assert_eq!(
            reader["claims"],
            json!({"registry_actor_kind":"service","registry_principal":"casework-reader","registry_purpose":"casework-sync"})
        );

        let administrator = clients.iter().find(|c| c["id"] == "administrator").unwrap();
        assert_eq!(administrator["accessProfiles"], json!([]));
        assert_eq!(administrator["scopes"], json!(["casework:admin"]));
        assert_eq!(
            administrator["claims"],
            json!({"registry_actor_kind":"human","registry_principal":"professional-review-administrator"})
        );
        assert!(administrator["claims"].get("registry_purpose").is_none());

        for role in ["supervisor", "staff"] {
            let client = clients.iter().find(|c| c["id"] == role).unwrap();
            assert_eq!(client["allowBregAccess"], true);
            assert_eq!(
                client["accessProfiles"],
                if role == "supervisor" {
                    json!(["reviewer"])
                } else {
                    json!([])
                }
            );
            assert_eq!(
                client["scopes"],
                json!([format!("casework:{role}"), "starter:reviewer"])
            );
            assert_eq!(client["claims"]["registry_purpose"], "starter-learning");
            assert_eq!(
                client["claims"]["registry_principal"],
                format!("professional-review-{role}")
            );
        }

        assert_eq!(
            plan.changes,
            json!([
                {"file":"dev-clients.yaml","path":"/clients/casework-reader","operation":"ensure_exact"},
                {"file":"dev-clients.yaml","path":"/clients/administrator","operation":"ensure_exact"},
                {"file":"dev-clients.yaml","path":"/clients/supervisor","operation":"ensure_exact"},
                {"file":"dev-clients.yaml","path":"/clients/staff","operation":"ensure_exact"},
                {"file":"dev-clients.yaml","path":"/clients/integration-requester","operation":"ensure_exact"},
                {"file":"dev-clients.yaml","path":"/reviewAuthorities/casework","operation":"ensure_exact"}
            ])
        );

        let write = plan.write.unwrap();
        write_atomic(&write.path, write.proposed.as_bytes()).unwrap();
        let written: Value = serde_json::from_slice(&fs::read(&write.path).unwrap()).unwrap();
        let written_ids: Vec<&str> = written["clients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect();
        // The pre-existing client stays first; the planned clients follow it.
        assert_eq!(
            written_ids,
            [
                "operator",
                "casework-reader",
                "administrator",
                "supervisor",
                "staff",
                "integration-requester"
            ]
        );
        assert_eq!(
            written["reviewAuthorities"]["casework"],
            json!({
                "endpoint":"http://127.0.0.1:8092",
                "profile":"integration-requester",
                "producerId":"registry-breg",
                "recoveryDays":7,
                "client":"integration-requester"
            })
        );
    }

    #[test]
    fn dev_clients_plan_reports_row_boundary_findings_and_still_writes_the_plan() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let registry = tempfile::tempdir().unwrap();
        fs::write(
            registry.path().join("dev-clients.yaml"),
            serde_json::to_vec(&json!({
                "version": 1,
                "clients": [
                    {"id":"operator","accessProfiles":["operator"],"scopes":["starter:operator"],"claims":{}}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        let (mut authored, request) = reviewer_fixture();
        authored["entities"] = json!([{
            "id": "request",
            "fields": [{"id": "region", "type": "string"}]
        }]);
        authored["accessProfiles"][0]["permissions"] = json!([{
            "entity": "request",
            "rowBoundaries": [{"field": "region", "claim": "allowed_regions", "operator": "equals"}]
        }]);

        let plan = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .unwrap();

        let [finding] = plan.findings.as_slice() else {
            panic!(
                "expected exactly one row-boundary finding, got {:?}",
                plan.findings
            );
        };
        assert_eq!(finding["severity"], "finding");
        assert_eq!(
            finding["path"],
            "registry.yaml:/accessProfiles/0/permissions/0/rowBoundaries"
        );
        let message = finding["message"].as_str().unwrap();
        assert!(message.contains("reviewer"), "{message}");
        assert!(message.contains("allowed_regions"), "{message}");

        // The rowBoundaries claim is not fabricated for the local reviewer
        // clients: the profile is still granted as-is, and BReg's runtime
        // enforcement (which fails closed when a token lacks the claim) is
        // what actually gates access, not this export.
        let supervisor = plan
            .patch
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "supervisor")
            .unwrap();
        assert_eq!(supervisor["accessProfiles"], json!(["reviewer"]));
        assert!(supervisor["claims"].get("allowed_regions").is_none());

        let write = plan.write.unwrap();
        write_atomic(&write.path, write.proposed.as_bytes()).unwrap();
        let written: Value = serde_json::from_slice(&fs::read(&write.path).unwrap()).unwrap();
        let written_supervisor = written["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "supervisor")
            .unwrap();
        assert_eq!(written_supervisor["accessProfiles"], json!(["reviewer"]));
    }

    #[test]
    fn dev_clients_plan_refuses_a_merged_total_over_the_breg_client_bound() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let registry = tempfile::tempdir().unwrap();
        let existing = (0..MAX_BREG_DEV_CLIENTS - 2)
            .map(|index| {
                json!({
                    "id": format!("existing-{index}"),
                    "accessProfiles": [],
                    "scopes": ["existing:read"],
                    "claims": {}
                })
            })
            .collect::<Vec<_>>();
        let original = serde_json::to_vec(&json!({"version": 1, "clients": existing})).unwrap();
        let path = registry.path().join("dev-clients.yaml");
        fs::write(&path, &original).unwrap();
        let (authored, request) = reviewer_fixture();

        let error = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .expect_err("the merged local client count must be bounded");
        assert!(format!("{error:#}").contains("32-client bound"));
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn dev_clients_plan_refuses_a_duplicate_breg_profile_binding() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let registry = tempfile::tempdir().unwrap();
        let original = serde_json::to_vec(&json!({
            "version": 1,
            "clients": [{
                "id": "existing-reader",
                "accessProfiles": [READER_CLIENT_ID],
                "scopes": [READER_SCOPE],
                "claims": {}
            }]
        }))
        .unwrap();
        let path = registry.path().join("dev-clients.yaml");
        fs::write(&path, &original).unwrap();
        let (authored, request) = reviewer_fixture();

        let error = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .expect_err("one BReg access profile cannot bind two local clients");
        assert!(format!("{error:#}").contains(READER_CLIENT_ID));
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn dev_clients_plan_registers_requester_with_no_breg_authority() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let policy_path = project.join("casework.yaml");
        let mut policy: Value = serde_norway::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
        policy["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"requester",
                "principalClaim":"registry_principal",
                "requiredScopes":["casework:request"],
                "role":"requester"
            }));
        fs::write(&policy_path, serde_norway::to_string(&policy).unwrap()).unwrap();

        let clients_path = project.join("dev-clients.yaml");
        let mut casework_clients: Value =
            serde_norway::from_slice(&fs::read(&clients_path).unwrap()).unwrap();
        casework_clients["clients"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"requester",
                "accessProfile":"requester",
                "scopes":["casework:request"],
                "claims":{}
            }));
        fs::write(
            &clients_path,
            serde_norway::to_string(&casework_clients).unwrap(),
        )
        .unwrap();

        let registry = tempfile::tempdir().unwrap();
        fs::write(
            registry.path().join("dev-clients.yaml"),
            serde_json::to_vec(&json!({"version":1,"clients":[]})).unwrap(),
        )
        .unwrap();
        let (authored, request) = reviewer_fixture();
        let plan = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .unwrap();
        let requester = plan
            .patch
            .as_array()
            .unwrap()
            .iter()
            .find(|client| client["id"] == "requester")
            .unwrap();
        assert_eq!(requester["accessProfiles"], json!([]));
        assert!(requester.get("allowBregAccess").is_none());
        assert_eq!(requester["scopes"], json!(["casework:request"]));
        assert_eq!(
            requester["claims"],
            json!({"registry_actor_kind":"service"})
        );
    }

    #[test]
    fn dev_clients_narrow_yaml_patch_preserves_comments() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let registry = tempfile::tempdir().unwrap();
        let input = "# operator callers\nversion: 1\nclients:\n  - id: operator\n    # do not rotate without notice\n    accessProfiles: [operator]\n    scopes: [starter:operator]\n    claims: {}\n";
        fs::write(registry.path().join("dev-clients.yaml"), input).unwrap();
        let (authored, request) = reviewer_fixture();
        let plan = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .unwrap();
        let clients = plan.patch.as_array().unwrap().clone();
        let mut expected: Value = serde_norway::from_str(input).unwrap();
        let mut changes = apply_dev_clients_candidate(&mut expected, &clients).unwrap();
        apply_local_review_authority_candidate(
            &mut expected,
            "casework",
            &json!({
                "endpoint":"http://127.0.0.1:8092",
                "profile":"integration-requester",
                "producerId":"registry-breg",
                "recoveryDays":7,
                "client":"integration-requester"
            }),
            &mut changes,
        )
        .unwrap();
        let write = plan.write.unwrap();
        assert!(write.proposed.contains("# operator callers"));
        assert!(write.proposed.contains("# do not rotate without notice"));
        assert_eq!(
            serde_norway::from_str::<Value>(&write.proposed).unwrap(),
            expected
        );
    }

    #[test]
    fn dev_clients_narrow_yaml_patch_extends_existing_review_authorities() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let registry = tempfile::tempdir().unwrap();
        let input = "# operator callers\nversion: 1\nclients: []\nreviewAuthorities:\n  # independently managed authority\n  appeals:\n    endpoint: http://127.0.0.1:9000\n    profile: appeals\n    producerId: appeals-producer\n    recoveryDays: 5\n    client: appeals-client\n";
        fs::write(registry.path().join("dev-clients.yaml"), input).unwrap();
        let (authored, request) = reviewer_fixture();
        let plan = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .unwrap();
        let write = plan.write.unwrap();
        assert!(write.proposed.contains("# independently managed authority"));
        assert_eq!(write.proposed.matches("reviewAuthorities:").count(), 1);
        let parsed: Value = serde_norway::from_str(&write.proposed).unwrap();
        assert!(parsed["reviewAuthorities"].get("appeals").is_some());
        assert!(parsed["reviewAuthorities"].get("casework").is_some());
    }

    #[test]
    fn dev_clients_reapply_is_byte_identical() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let registry = tempfile::tempdir().unwrap();
        fs::write(
            registry.path().join("dev-clients.yaml"),
            serde_json::to_vec(&json!({"version":1,"clients":[]})).unwrap(),
        )
        .unwrap();
        let (authored, request) = reviewer_fixture();
        let first = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .unwrap();
        let write = first.write.unwrap();
        write_atomic(&write.path, write.proposed.as_bytes()).unwrap();
        let second = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .unwrap();
        let rewrite = second.write.unwrap();
        assert_eq!(rewrite.proposed.as_bytes(), write.proposed.as_bytes());
        assert_eq!(
            fs::read(&rewrite.path).unwrap(),
            rewrite.proposed.as_bytes()
        );
    }

    #[test]
    fn dev_clients_refuses_existing_client_with_different_content_naming_only_the_id() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let registry = tempfile::tempdir().unwrap();
        let original = serde_json::to_vec(&json!({
            "version": 1,
            "clients": [
                {"id":"staff","accessProfiles":[],"scopes":["unexpected:scope"],"claims":{}}
            ]
        }))
        .unwrap();
        fs::write(registry.path().join("dev-clients.yaml"), &original).unwrap();
        let (authored, request) = reviewer_fixture();
        let error = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("staff"), "{message}");
        assert!(!message.contains("unexpected:scope"), "{message}");
        assert_eq!(
            fs::read(registry.path().join("dev-clients.yaml")).unwrap(),
            original
        );
    }

    #[test]
    fn dev_clients_plan_never_writes_before_an_explicit_write_atomic_call() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let registry = tempfile::tempdir().unwrap();
        let original = serde_json::to_vec(&json!({"version":1,"clients":[]})).unwrap();
        fs::write(registry.path().join("dev-clients.yaml"), &original).unwrap();
        let (authored, request) = reviewer_fixture();
        let plan = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .unwrap();
        assert!(
            plan.write.is_some(),
            "a present dev-clients.yaml must produce a pending write"
        );
        assert_eq!(
            fs::read(registry.path().join("dev-clients.yaml")).unwrap(),
            original,
            "planning must never write to disk by itself"
        );
    }

    #[test]
    fn dev_clients_reports_absent_when_breg_project_has_no_dev_clients_file() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let registry = tempfile::tempdir().unwrap();
        let (authored, request) = reviewer_fixture();
        let plan = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .unwrap();
        assert_eq!(plan.patch, json!("absent"));
        assert_eq!(plan.changes, json!([]));
        assert!(plan.write.is_none());
    }

    #[test]
    fn dev_clients_reports_absent_when_casework_project_has_no_dev_clients_file() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        fs::remove_file(project.join("dev-clients.yaml")).unwrap();
        let registry = tempfile::tempdir().unwrap();
        fs::write(
            registry.path().join("dev-clients.yaml"),
            b"version: 1\nclients: []\n",
        )
        .unwrap();
        let (authored, request) = reviewer_fixture();
        let plan = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&request)],
        )
        .unwrap();
        assert_eq!(plan.patch, json!("absent"));
        assert_eq!(plan.changes, json!([]));
        assert!(plan.write.is_none());
    }

    #[test]
    fn reviewer_authority_bails_on_wrong_principal_claim_or_disagreeing_purpose() {
        let mismatched_principal = json!({
            "accessProfiles": [
                {"id":"reviewer","principalClaim":"sub","requiredScopes":["starter:reviewer"],"requiredPurposes":["starter-learning"]}
            ]
        });
        let request = json!({"reviewPermissions":[{"profile":"reviewer"}],"applyPermissions":[]});
        assert!(reviewer_authority(&mismatched_principal, &request, &reviewer_clients()).is_err());

        let disagreeing_purpose = json!({
            "accessProfiles": [
                {"id":"reviewer","principalClaim":"registry_principal","requiredScopes":["starter:reviewer"],"requiredPurposes":["starter-learning"]},
                {"id":"approver","principalClaim":"registry_principal","requiredScopes":["starter:approver"],"requiredPurposes":["starter-approval"]}
            ]
        });
        let request = json!({"reviewPermissions":[{"profile":"reviewer"}],"applyPermissions":[{"profile":"approver"}]});
        assert!(reviewer_authority(&disagreeing_purpose, &request, &reviewer_clients()).is_err());
    }

    #[test]
    fn reviewer_authority_requires_every_human_casework_client() {
        let (mut authored, request) = reviewer_fixture();
        authored["accessProfiles"][0]
            .as_object_mut()
            .unwrap()
            .remove("actorKind");
        assert!(reviewer_authority(&authored, &request, &reviewer_clients()).is_err());

        let (mut authored, request) = reviewer_fixture();
        authored["accessProfiles"][0]["requesterClients"] = json!(["supervisor"]);
        assert!(reviewer_authority(&authored, &request, &reviewer_clients()).is_err());
    }

    #[test]
    fn reviewer_authority_accepts_a_profile_shared_with_other_clients_and_warns() {
        let (mut authored, request) = reviewer_fixture();
        authored["accessProfiles"][0]["requesterClients"] =
            json!(["staff", "supervisor", "other-project-staff"]);
        let authority = reviewer_authority(&authored, &request, &reviewer_clients()).unwrap();
        assert_eq!(authority.warnings.len(), 1);
        assert!(authority.warnings[0].contains("reviewer"));
        assert!(authority.warnings[0].contains("other-project-staff"));

        let (authored, request) = reviewer_fixture();
        let authority = reviewer_authority(&authored, &request, &reviewer_clients()).unwrap();
        assert!(authority.warnings.is_empty());
    }

    #[test]
    fn reviewer_authority_accepts_unrestricted_purpose_profiles() {
        let unrestricted = json!({
            "accessProfiles": [
                {"id":"reviewer","principalClaim":"registry_principal","actorKind":"human","requesterClients":["staff","supervisor"]},
                {"id":"approver","principalClaim":"registry_principal","actorKind":"human","requesterClients":["staff","supervisor"],"requiredScopes":[],"requiredPurposes":[]}
            ]
        });
        let request = json!({"reviewPermissions":[{"profile":"reviewer"}],"applyPermissions":[{"profile":"approver"}]});
        let authority = reviewer_authority(&unrestricted, &request, &reviewer_clients()).unwrap();
        assert!(authority.scopes.is_empty());
        assert_eq!(authority.purpose, None);

        let client = json!({
            "id":"staff",
            "scopes":["casework:staff"],
            "claims":{"registry_principal":"staff-1"}
        });
        let merged =
            human_dev_client(&client, "staff", "registry_principal", Some(&authority)).unwrap();
        assert!(merged["claims"].get("registry_purpose").is_none());
    }

    /// `accessProfiles` fixture shared by the row-boundary tests below: an
    /// "operator" profile with no row boundaries, and a "reviewer" profile
    /// (at the real index 1, which the finding and error paths must name)
    /// whose one permission on entity "request" carries the row boundary
    /// under test.
    fn row_boundary_fixture(row_boundary: Value) -> (Value, Value) {
        let authored = json!({
            "entities": [{
                "id": "request",
                "fields": [
                    {"id": "region", "type": "string"},
                    {"id": "flagged", "type": "boolean"}
                ]
            }],
            "accessProfiles": [
                {
                    "id":"operator",
                    "principalClaim":"registry_principal",
                    "actorKind":"human",
                    "requesterClients":["staff","supervisor"]
                },
                {
                    "id":"reviewer",
                    "principalClaim":"registry_principal",
                    "actorKind":"human",
                    "requesterClients":["staff","supervisor"],
                    "permissions":[{
                        "entity":"request",
                        "rowBoundaries":[row_boundary]
                    }]
                }
            ]
        });
        let request = json!({"reviewPermissions":[{"profile":"reviewer"}],"applyPermissions":[]});
        (authored, request)
    }

    #[test]
    fn reviewer_authority_reports_a_finding_for_a_row_boundary_claim_equals_over_a_string_field() {
        let (authored, request) = row_boundary_fixture(
            json!({"field":"region","claim":"allowed_regions","operator":"equals"}),
        );

        let authority = reviewer_authority(&authored, &request, &reviewer_clients())
            .expect("an equals row boundary over a string field must not refuse the pairing");
        assert_eq!(authority.profiles, BTreeSet::from(["reviewer".to_owned()]));
        let [finding] = authority.row_boundary_findings.as_slice() else {
            panic!(
                "expected exactly one row-boundary finding, got {:?}",
                authority.row_boundary_findings
            );
        };
        assert_eq!(finding["severity"], "finding");
        // "reviewer" is at index 1 in accessProfiles: the location must name
        // that real index, not the profile id, and the permissions[] entry
        // rowBoundaries is nested under.
        assert_eq!(
            finding["path"],
            "registry.yaml:/accessProfiles/1/permissions/0/rowBoundaries"
        );
        let message = finding["message"].as_str().unwrap();
        assert!(message.contains("reviewer"), "{message}");
        assert!(message.contains("allowed_regions"), "{message}");
        assert!(message.contains("string"), "{message}");
        let suggested_action = finding["suggestedAction"].as_str().unwrap();
        assert!(suggested_action.contains("reviewer"), "{suggested_action}");
        assert!(
            suggested_action.contains("allowed_regions"),
            "{suggested_action}"
        );
    }

    #[test]
    fn reviewer_authority_refuses_a_row_boundary_claim_using_operator_in() {
        let (authored, request) = row_boundary_fixture(
            json!({"field":"region","claim":"allowed_regions","operator":"in"}),
        );

        let error = reviewer_authority(&authored, &request, &reviewer_clients()).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("reviewer"), "{message}");
        assert!(message.contains("allowed_regions"), "{message}");
        assert!(message.contains("`in`"), "{message}");
        assert!(message.contains("string"), "{message}");
    }

    #[test]
    fn reviewer_authority_refuses_a_row_boundary_claim_equals_over_a_boolean_field() {
        let (authored, request) = row_boundary_fixture(
            json!({"field":"flagged","claim":"allowed_flag","operator":"equals"}),
        );

        let error = reviewer_authority(&authored, &request, &reviewer_clients()).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("reviewer"), "{message}");
        assert!(message.contains("allowed_flag"), "{message}");
        assert!(message.contains("`boolean`"), "{message}");
    }

    #[test]
    fn human_dev_client_bails_when_existing_purpose_claim_conflicts() {
        let authority = ReviewerAuthority {
            profiles: BTreeSet::from(["reviewer".to_owned()]),
            scopes: BTreeSet::from(["starter:reviewer".to_owned()]),
            purpose: Some("starter-learning".to_owned()),
            row_boundary_findings: Vec::new(),
            warnings: Vec::new(),
        };
        let client = json!({
            "id":"staff",
            "scopes":["casework:staff"],
            "claims":{"registry_principal":"staff-1","registry_purpose":"other-purpose"}
        });
        let error =
            human_dev_client(&client, "staff", "registry_principal", Some(&authority)).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("staff"), "{message}");
        assert!(!message.contains("other-purpose"), "{message}");
        assert!(!message.contains("starter-learning"), "{message}");

        let matching = json!({
            "id":"staff",
            "scopes":["casework:staff"],
            "claims":{"registry_principal":"staff-1","registry_purpose":"starter-learning"}
        });
        let merged =
            human_dev_client(&matching, "staff", "registry_principal", Some(&authority)).unwrap();
        assert_eq!(merged["claims"]["registry_purpose"], "starter-learning");
    }

    #[test]
    fn human_dev_client_maps_the_configured_casework_principal_for_breg_review() {
        let authority = ReviewerAuthority {
            profiles: BTreeSet::from(["reviewer".to_owned()]),
            scopes: BTreeSet::from(["starter:reviewer".to_owned()]),
            purpose: None,
            row_boundary_findings: Vec::new(),
            warnings: Vec::new(),
        };
        let client = json!({
            "id":"staff",
            "scopes":["casework:staff"],
            "claims":{"employee_id":"employee-123"}
        });
        let merged = human_dev_client(&client, "staff", "employee_id", Some(&authority)).unwrap();

        assert_eq!(merged["claims"]["employee_id"], "employee-123");
        assert_eq!(merged["claims"][READER_PRINCIPAL_CLAIM], "employee-123");

        let conflicting = json!({
            "id":"staff",
            "scopes":["casework:staff"],
            "claims":{"employee_id":"employee-123","registry_principal":"other-person"}
        });
        let error =
            human_dev_client(&conflicting, "staff", "employee_id", Some(&authority)).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("staff"), "{message}");
        assert!(!message.contains("employee-123"), "{message}");
        assert!(!message.contains("other-person"), "{message}");
    }

    #[test]
    fn human_dev_client_refuses_a_session_qualified_subject_for_breg_review() {
        let authority = ReviewerAuthority {
            profiles: BTreeSet::from(["reviewer".to_owned()]),
            scopes: BTreeSet::from(["starter:reviewer".to_owned()]),
            purpose: None,
            row_boundary_findings: Vec::new(),
            warnings: Vec::new(),
        };
        let client = json!({
            "id":"staff",
            "scopes":["casework:staff"],
            "claims":{"registry_actor_kind":"human"}
        });

        let refusal = human_dev_client(&client, "staff", "sub", Some(&authority))
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("session-qualified"), "{refusal}");
    }

    #[test]
    fn human_dev_client_refuses_authority_over_breg_scope_or_claim_bounds() {
        let authority = ReviewerAuthority {
            profiles: BTreeSet::from(["reviewer".to_owned()]),
            scopes: BTreeSet::from(["starter:reviewer".to_owned()]),
            purpose: None,
            row_boundary_findings: Vec::new(),
            warnings: Vec::new(),
        };
        let scopes = (0..MAX_BREG_DEV_CLIENT_SCOPES)
            .map(|index| format!("casework:scope-{index}"))
            .collect::<Vec<_>>();
        let too_many_scopes = json!({
            "id":"staff",
            "scopes":scopes,
            "claims":{"registry_principal":"staff-1"}
        });
        let error = human_dev_client(
            &too_many_scopes,
            "staff",
            "registry_principal",
            Some(&authority),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("scope or claim bounds"));

        let mut claims = serde_json::Map::new();
        for index in 0..MAX_BREG_DEV_CLIENT_CLAIMS - 1 {
            claims.insert(format!("claim_{index}"), json!(format!("value-{index}")));
        }
        claims.insert("employee_id".to_owned(), json!("employee-123"));
        let too_many_claims = json!({
            "id":"supervisor",
            "scopes":["casework:supervisor"],
            "claims":claims
        });
        let error = human_dev_client(
            &too_many_claims,
            "supervisor",
            "employee_id",
            Some(&ReviewerAuthority {
                profiles: BTreeSet::from(["reviewer".to_owned()]),
                scopes: BTreeSet::new(),
                purpose: None,
                row_boundary_findings: Vec::new(),
                warnings: Vec::new(),
            }),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("scope or claim bounds"));
    }

    #[test]
    fn candidate_staging_excludes_private_runtime_and_vcs_state() {
        let registry = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        fs::write(registry.path().join("registry.yaml"), "apiVersion: v1\n").unwrap();
        fs::create_dir_all(registry.path().join("schemas")).unwrap();
        fs::write(registry.path().join("schemas/entity.json"), "{}").unwrap();
        fs::create_dir_all(registry.path().join(".breg/dev")).unwrap();
        fs::write(registry.path().join(".breg/dev/private"), "secret").unwrap();
        fs::create_dir_all(registry.path().join(".git")).unwrap();
        fs::write(registry.path().join(".git/config"), "private").unwrap();

        copy_tree(registry.path(), staging.path(), registry.path()).unwrap();

        assert!(staging.path().join("registry.yaml").is_file());
        assert!(staging.path().join("schemas/entity.json").is_file());
        assert!(!staging.path().join(".breg").exists());
        assert!(!staging.path().join(".git").exists());
    }

    #[test]
    fn dev_client_yaml_quotes_every_authored_scalar() {
        let client = json!({
            "id": "client",
            "accessProfiles": [],
            "allowBregAccess": true,
            "scopes": ["read,write", "value: scoped", "true"],
            "claims": {"purpose": "review: licensing", "enabled": "false"}
        });
        let rendered = format!(
            "version: 1\nclients:\n{}",
            render_dev_client_yaml_block(&client).unwrap()
        );
        let parsed: Value = serde_norway::from_str(&rendered).unwrap();
        assert_eq!(parsed["clients"][0], client);
    }

    fn two_entity_policy(project: &Path) {
        fs::write(project.join("casework.yaml"), serde_json::to_vec(&json!({
            "sources": [{"id":"farmers", "adapter":"breg", "requests":[
                {"entity":"correction", "projection":["region"]},
                {"entity":"renewal"}
            ]}],
            "reviewKinds":[
                {"id":"registry-correction", "purpose":"approval", "contextStrategy":"source"},
                {"id":"registry-renewal", "purpose":"approval", "contextStrategy":"source"}
            ],
            "reviewProducers":[{
                "id":"registry-breg", "profile":"integration-requester", "recoveryDays":7,
                "sourceNamespaces":["farmers"], "kinds":["registry-correction", "registry-renewal"]
            }]
        })).unwrap()).unwrap();
    }

    fn two_entity_explanation() -> Value {
        json!({"revision":"r1", "explanation":{"requests":[
            {
                "requestEntity":"renewal",
                "review":{"authority":"casework-renewals","policyId":"registry-renewal"},
                "onApproved":{"mode":"automatic","executor":"registry-automatic"},
                "applyPermissions":[{"profile":"automatic-applier"}]
            },
            {
                "requestEntity":"correction",
                "review":{"authority":"casework-main","policyId":"registry-correction"},
                "onApproved":{"mode":"manual"}
            }
        ]}})
    }

    #[test]
    fn source_import_selects_every_declared_request_entity_in_declaration_order() {
        let project = tempfile::tempdir().unwrap();
        two_entity_policy(project.path());
        let report = two_entity_explanation();

        let selected = select_requests(project.path(), "farmers", "farmers", &report).unwrap();

        let entities = selected
            .iter()
            .map(SelectedRequest::entity)
            .collect::<Vec<_>>();
        assert_eq!(entities, ["correction", "renewal"]);
        assert_eq!(selected[0].authority, "casework-main");
        assert_eq!(selected[1].policy_id, "registry-renewal");
        assert!(matches!(
            selected[1].application,
            ApplicationPlan::Automatic { .. }
        ));
        let metadata = json!({"fields":[{"field":"region","apiName":"region"}]});
        assert_eq!(
            source_projection(project.path(), "farmers", "correction", &metadata).unwrap(),
            ["region"]
        );
        assert!(
            source_projection(project.path(), "farmers", "renewal", &metadata)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn source_import_refuses_a_declared_entity_absent_from_breg_metadata() {
        let project = tempfile::tempdir().unwrap();
        two_entity_policy(project.path());
        let mut report = two_entity_explanation();
        report["explanation"]["requests"]
            .as_array_mut()
            .unwrap()
            .remove(0);

        let error = select_requests(project.path(), "farmers", "farmers", &report)
            .err()
            .expect("every declared entity must be compiled by BReg");
        assert!(format!("{error:#}").contains("renewal"));
    }

    #[test]
    fn source_import_refuses_a_request_entity_declared_twice() {
        let project = tempfile::tempdir().unwrap();
        two_entity_policy(project.path());
        let mut policy: Value =
            serde_json::from_slice(&fs::read(project.path().join("casework.yaml")).unwrap())
                .unwrap();
        policy["sources"][0]["requests"][1]["entity"] = json!("correction");
        fs::write(
            project.path().join("casework.yaml"),
            serde_json::to_vec(&policy).unwrap(),
        )
        .unwrap();

        let error = select_requests(
            project.path(),
            "farmers",
            "farmers",
            &two_entity_explanation(),
        )
        .err()
        .expect("each request entity is named once");
        assert!(format!("{error:#}").contains("correction"));
    }

    #[test]
    fn source_description_lists_every_request_only_when_there_are_several() {
        let project = tempfile::tempdir().unwrap();
        two_entity_policy(project.path());
        let report = two_entity_explanation();
        let selected = select_requests(project.path(), "farmers", "farmers", &report).unwrap();

        let single = source_description("farmers", &selected[..1], &report).unwrap();
        assert_eq!(
            single["apiVersion"],
            "registry.registrystack.org/casework-source-description/v1alpha1"
        );
        assert_eq!(single["request"]["requestEntity"], "correction");
        assert!(single.get("requests").is_none());

        let several = source_description("farmers", &selected, &report).unwrap();
        assert_eq!(
            several["apiVersion"],
            "registry.registrystack.org/casework-source-description/v1alpha2"
        );
        assert!(several.get("request").is_none());
        let entities = several["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|request| request["requestEntity"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(entities, ["correction", "renewal"]);
    }

    #[test]
    fn runtime_binding_names_each_review_authority_and_executor_once() {
        let project = tempfile::tempdir().unwrap();
        two_entity_policy(project.path());
        let report = two_entity_explanation();
        let mut selected = select_requests(project.path(), "farmers", "farmers", &report).unwrap();

        let binding = runtime_binding("farmers", "farmers", &selected).unwrap();
        let parsed: Value = serde_norway::from_str(&binding).unwrap();
        let authorities = parsed["reviewAuthorities"].as_object().unwrap();
        assert_eq!(
            authorities.keys().collect::<Vec<_>>(),
            ["casework-main", "casework-renewals"]
        );
        assert_eq!(
            parsed["reviewExecutors"]["registry-automatic"]["accessProfile"],
            "automatic-applier"
        );

        selected[1].authority = "casework-main".to_owned();
        let shared = runtime_binding("farmers", "farmers", &selected).unwrap();
        let parsed: Value = serde_norway::from_str(&shared).unwrap();
        assert_eq!(parsed["reviewAuthorities"].as_object().unwrap().len(), 1);

        selected[1].recovery_days = 3;
        let error = runtime_binding("farmers", "farmers", &selected)
            .expect_err("one review authority cannot carry two producer admissions");
        assert!(format!("{error:#}").contains("casework-main"));
    }

    #[test]
    fn candidate_pairs_every_request_entity_in_one_pass() {
        let input = "# keep authored context\nentities:\n  - id: correction\n    route: corrections\n  - id: renewal\n    route: renewals\naccessProfiles: []\n";
        let mut authored: Value = serde_norway::from_str(input).unwrap();
        let readers = vec![
            ("correction".to_owned(), record_reader(&[])),
            ("renewal".to_owned(), record_reader(&[])),
        ];

        let (changes, proposed) =
            apply_breg_candidates(&mut authored, input.as_bytes(), &readers).unwrap();

        assert!(proposed.contains("# keep authored context"));
        assert_eq!(
            serde_norway::from_str::<Value>(&proposed).unwrap(),
            authored
        );
        for entity in authored["entities"].as_array().unwrap() {
            assert_eq!(entity["hooks"][0]["id"], "casework-lifecycle-v1");
        }
        let permitted = authored["accessProfiles"][0]["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|permission| permission["entity"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(permitted, ["correction", "renewal"]);
        let paths = changes
            .iter()
            .map(|change| change["path"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                "/entities/correction/hooks/casework-lifecycle-v1",
                "/accessProfiles/casework-reader",
                "/entities/renewal/hooks/casework-lifecycle-v1",
            ]
        );
    }

    #[test]
    fn dev_clients_plan_binds_every_request_authority_and_reviewer_profile() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        crate::project::init(&project, "professional-review").unwrap();
        let registry = tempfile::tempdir().unwrap();
        fs::write(
            registry.path().join("dev-clients.yaml"),
            "version: 1\nclients: []\n",
        )
        .unwrap();
        let (mut authored, correction) = reviewer_fixture();
        let mut renewal_profile = authored["accessProfiles"][0].clone();
        renewal_profile["id"] = json!("renewal-reviewer");
        renewal_profile["requiredScopes"] = json!(["starter:renewals"]);
        authored["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .push(renewal_profile);
        let renewal = json!({"reviewPermissions": [{"profile": "renewal-reviewer"}]});
        let mut renewal_request = selected_request(&renewal);
        renewal_request.authority = "casework-renewals".to_owned();

        let plan = plan_breg_dev_clients(
            registry.path(),
            &project,
            &authored,
            &[selected_request(&correction), renewal_request],
        )
        .unwrap();

        let parsed: Value = serde_norway::from_str(&plan.write.unwrap().proposed).unwrap();
        assert!(parsed["reviewAuthorities"].get("casework").is_some());
        assert!(parsed["reviewAuthorities"]
            .get("casework-renewals")
            .is_some());
        let supervisor = parsed["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|client| client["id"] == "supervisor")
            .unwrap();
        assert_eq!(
            supervisor["accessProfiles"],
            json!(["renewal-reviewer", "reviewer"])
        );
        let scopes = supervisor["scopes"].as_array().unwrap();
        assert!(scopes.contains(&json!("starter:reviewer")));
        assert!(scopes.contains(&json!("starter:renewals")));
    }
}
