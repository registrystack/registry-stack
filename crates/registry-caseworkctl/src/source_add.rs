// SPDX-License-Identifier: Apache-2.0

use crate::SourceAddArgs;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_PROVIDER_OUTPUT: usize = 2 * 1024 * 1024;
// Keep the generated local teaching identities within bregctl's closed v1
// dev-client format before source add offers to write them.
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
/// The Mint claim a local BReg client's access token carries its purpose under.
const PURPOSE_CLAIM: &str = "registry_purpose";

pub(super) fn run(args: &SourceAddArgs) -> Result<Value> {
    validate_id(&args.source_id)?;
    let registry = canonical_dir(&args.registry, "BReg project")?;
    let project = canonical_dir(&args.project, "Casework project")?;
    check_version(&args.bregctl_bin)?;
    let checked = invoke(&args.bregctl_bin, &["--format", "json", "check"], &registry)?;
    require_ok("check", &checked)?;
    let explained = invoke(
        &args.bregctl_bin,
        &["--format", "json", "explain", "change-requests"],
        &registry,
    )?;
    require_ok("explain change-requests", &explained)?;
    let request = select_request(&project, &args.source_id, &explained)?;
    let request_entity = request.entity().to_owned();
    let projection = source_projection(&project, &args.source_id, request.0)?;
    let registry_yaml = registry.join("registry.yaml");
    let bytes = fs::read(&registry_yaml).context("reading BReg registry.yaml")?;
    if bytes.len() > MAX_PROVIDER_OUTPUT {
        bail!("BReg registry.yaml exceeds the source-add byte limit");
    }
    let mut authored: Value = serde_norway::from_slice(&bytes)
        .context("parsing BReg registry.yaml without duplicate or custom YAML values")?;
    let changes = apply_breg_candidate(&mut authored, &request_entity, &projection)?;
    let proposed =
        render_candidate_preserving_authored_text(&bytes, &request_entity, &authored, &projection)?;
    let candidate_explanation = verify_candidate(&args.bregctl_bin, &registry, &proposed)?;
    let candidate_request = select_request(&project, &args.source_id, &candidate_explanation)?;
    let (event_patch, reader_patch) = candidate_fragments(&request_entity, &projection);
    let dev_clients_plan =
        plan_breg_dev_clients(&registry, &project, &authored, candidate_request.0)?;
    let description =
        source_description(&args.source_id, candidate_request, &candidate_explanation)?;
    let description_path = project
        .join("sources")
        .join(format!("{}.json", args.source_id));
    let binding_path = project
        .join("sources")
        .join(format!("{}.breg-runtime.yaml", args.source_id));
    let binding = runtime_binding(&args.source_id);
    let mut breg_authoring_changes = changes.as_array().cloned().unwrap_or_default();
    if let Value::Array(dev_clients_changes) = &dev_clients_plan.changes {
        breg_authoring_changes.extend(dev_clients_changes.iter().cloned());
    }
    let mut report = json!({
        "ok": true,
        "command": "source add",
        "status": if args.apply { "applied" } else { "preview" },
        "sourceId": args.source_id,
        "registry": registry,
        "project": project,
        "sourceDescription": description_path,
        "bregRuntimeBinding": binding_path,
        "bregAuthoringChanges": breg_authoring_changes,
        "bregAuthoringPatch": {"event": event_patch, "accessProfile": reader_patch, "devClients": dev_clients_plan.patch},
        "activation": "not_performed",
        "next": if args.apply {
            json!(["Review the generated BReg runtime binding, provision its secret reference, and let the launcher activate each product through its normal path.", "Run caseworkctl doctor --runtime-config FILE after authenticated directory setup."])
        } else {
            json!(["Review these exact local changes, then repeat source add with --apply."])
        }
    });
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
/// from the selected BReg request's review and apply access profiles.
struct ReviewerAuthority {
    scopes: BTreeSet<String>,
    purpose: Option<String>,
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
/// correspond to, and, when the BReg project has a dev-clients.yaml to patch,
/// what apply needs to write it.
#[derive(Debug)]
struct DevClientsPlan {
    patch: Value,
    changes: Value,
    write: Option<DevClientsWrite>,
}

struct SelectedRequest<'a>(&'a Value);

impl SelectedRequest<'_> {
    fn entity(&self) -> &str {
        self.0["requestEntity"].as_str().expect("validated entity")
    }
}

fn select_request<'a>(
    project: &Path,
    source_id: &str,
    report: &'a Value,
) -> Result<SelectedRequest<'a>> {
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
    if requests.len() != 1 {
        bail!("the checkpoint supports exactly one request declaration");
    }
    let entity = requests[0]["entity"]
        .as_str()
        .context("source request entity is missing")?;
    let choices = report
        .pointer("/explanation/requests")
        .and_then(Value::as_array)
        .context("BReg explanation omitted requests")?;
    let selected = choices
        .iter()
        .find(|candidate| candidate["requestEntity"] == entity)
        .context("declared request entity is absent from BReg compiled metadata")?;
    let stages = selected["stages"]
        .as_array()
        .context("BReg request stages are absent")?;
    if selected["reviewMode"] != "staged"
        || !(1..=32).contains(&stages.len())
        || stages.iter().any(|stage| {
            stage["approvals"]
                .as_u64()
                .is_none_or(|count| !(1..=32).contains(&count))
        })
        || selected.pointer("/application/mode") != Some(&Value::String("manual".into()))
    {
        bail!(
            "Casework requires staged review with positive approval counts and manual application"
        );
    }
    Ok(SelectedRequest(selected))
}

fn source_projection(project: &Path, source_id: &str, metadata: &Value) -> Result<Vec<String>> {
    let policy = load_casework_policy(project)?;
    let source = policy["sources"]
        .as_array()
        .and_then(|sources| sources.iter().find(|source| source["id"] == source_id))
        .context("source id is not declared in casework.yaml")?;
    let configured = &source["requests"][0];
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

fn reader_fields(projection: &[String]) -> Vec<String> {
    std::iter::once("record".to_owned())
        .chain(projection.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn load_casework_policy(project: &Path) -> Result<Value> {
    let bytes = fs::read(project.join("casework.yaml")).context("reading casework.yaml")?;
    let root: Value = serde_norway::from_slice(&bytes).context("parsing casework.yaml")?;
    Ok(root)
}

fn apply_breg_candidate(root: &mut Value, entity_id: &str, projection: &[String]) -> Result<Value> {
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
    let events = entity_object
        .entry("events")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("BReg entity events must be an array")?;
    let (event, profile) = candidate_fragments(entity_id, projection);
    match events
        .iter()
        .find(|item| item["id"] == "casework-lifecycle-v1")
    {
        Some(existing) if existing != &event => {
            bail!("BReg event casework-lifecycle-v1 already exists with different content")
        }
        None => events.push(event),
        _ => {}
    }
    let profiles = object
        .get_mut("accessProfiles")
        .and_then(Value::as_array_mut)
        .context("BReg registry.yaml has no accessProfiles")?;
    match profiles.iter().find(|item| item["id"] == READER_CLIENT_ID) {
        Some(existing) if existing != &profile => {
            bail!("BReg access profile {READER_CLIENT_ID} already exists with different content")
        }
        None => profiles.push(profile),
        _ => {}
    }
    Ok(json!([
        {"file":"registry.yaml","path":format!("/entities/{entity_id}/events/casework-lifecycle-v1"),"operation":"ensure_exact"},
        {"file":"registry.yaml","path":format!("/accessProfiles/{READER_CLIENT_ID}"),"operation":"ensure_exact"}
    ]))
}

fn candidate_fragments(entity_id: &str, projection: &[String]) -> (Value, Value) {
    let fields = reader_fields(projection);
    (
        json!({"id":"casework-lifecycle-v1","trigger":"request_lifecycle","projection":["record"],"webhook":{"destinationId":"casework"}}),
        json!({
            "id":READER_CLIENT_ID, "default":false, "principalClaim":READER_PRINCIPAL_CLAIM,
            "requiredScopes":[READER_SCOPE], "requiredPurposes":[READER_PURPOSE],
            "grants":[{"entity":entity_id,"operations":["get","list"],"readableFields":fields,"readableRequestFields":["review_state"],"rowBoundaries":[]}]
        }),
    )
}

fn render_candidate_preserving_authored_text(
    original: &[u8],
    entity_id: &str,
    expected: &Value,
    projection: &[String],
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
    let has_event = parsed["entities"]
        .as_array()
        .and_then(|entities| entities.iter().find(|entity| entity["id"] == entity_id))
        .and_then(|entity| entity["events"].as_array())
        .is_some_and(|events| {
            events
                .iter()
                .any(|event| event["id"] == "casework-lifecycle-v1")
        });
    let has_profile = parsed["accessProfiles"].as_array().is_some_and(|profiles| {
        profiles
            .iter()
            .any(|profile| profile["id"] == READER_CLIENT_ID)
    });
    let mut rendered = text.to_owned();
    if !has_event {
        rendered = insert_entity_event(&rendered, entity_id)?;
    }
    if !has_profile {
        rendered = insert_access_profile(&rendered, entity_id, projection)?;
    }
    let round_trip: Value =
        serde_norway::from_str(&rendered).context("parsing narrow BReg YAML patch")?;
    if &round_trip != expected {
        bail!("narrow BReg YAML patch changed unexpected authored content; no files were written");
    }
    Ok(rendered)
}

fn insert_entity_event(text: &str, entity_id: &str) -> Result<String> {
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
    let events = (start + 1..end).find(|index| {
        leading_spaces(lines[*index]) == field_indent && lines[*index].trim() == "events:"
    });
    let insertion = if let Some(events) = events {
        (events + 1..end)
            .find(|index| {
                leading_spaces(lines[*index]) == field_indent
                    && !lines[*index].trim().is_empty()
                    && !lines[*index].trim_start().starts_with('#')
            })
            .unwrap_or(end)
    } else {
        end
    };
    let block = if events.is_some() {
        format!("{}- id: casework-lifecycle-v1\n{}  trigger: request_lifecycle\n{}  projection: [record]\n{}  webhook: {{destinationId: casework}}\n", " ".repeat(field_indent + 2), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2))
    } else {
        format!("{}events:\n{}- id: casework-lifecycle-v1\n{}  trigger: request_lifecycle\n{}  projection: [record]\n{}  webhook: {{destinationId: casework}}\n", " ".repeat(field_indent), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2), " ".repeat(field_indent + 2))
    };
    Ok(insert_at_line(&lines, insertion, &block))
}

fn insert_access_profile(text: &str, entity_id: &str, projection: &[String]) -> Result<String> {
    let fields = serde_json::to_string(&reader_fields(projection))?;
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    let start = lines
        .iter()
        .position(|line| line.trim() == "accessProfiles:")
        .context("narrow YAML patch could not locate accessProfiles")?;
    let end = (start + 1..lines.len())
        .find(|index| {
            leading_spaces(lines[*index]) == 0
                && !lines[*index].trim().is_empty()
                && !lines[*index].trim_start().starts_with('#')
        })
        .unwrap_or(lines.len());
    let block = format!("  - id: {READER_CLIENT_ID}\n    default: false\n    principalClaim: {READER_PRINCIPAL_CLAIM}\n    requiredScopes: [{READER_SCOPE}]\n    requiredPurposes: [{READER_PURPOSE}]\n    grants:\n      - entity: {entity_id}\n        operations: [get, list]\n        readableFields: {fields}\n        readableRequestFields: [review_state]\n        rowBoundaries: []\n");
    Ok(insert_at_line(&lines, end, &block))
}

fn insert_at_line(lines: &[&str], index: usize, block: &str) -> String {
    let mut output =
        String::with_capacity(lines.iter().map(|line| line.len()).sum::<usize>() + block.len());
    output.extend(lines[..index].iter().copied());
    output.push_str(block);
    output.extend(lines[index..].iter().copied());
    output
}

fn leading_spaces(line: &str) -> usize {
    line.bytes().take_while(|byte| *byte == b' ').count()
}

/// The local BReg client exercising the casework-reader access profile, with
/// the same id, scope, purpose, and principal claim `candidate_fragments`
/// authors the profile itself with.
fn reader_dev_client() -> Value {
    json!({
        "id": READER_CLIENT_ID,
        "accessProfiles": [READER_CLIENT_ID],
        "scopes": [READER_SCOPE],
        "claims": {READER_PRINCIPAL_CLAIM: READER_CLIENT_ID, PURPOSE_CLAIM: READER_PURPOSE},
    })
}

/// The scopes and purpose every Casework staff or supervisor dev client must
/// carry to act as a reviewer on the selected BReg request: the union of
/// `requiredScopes` from every distinct access profile named in its
/// `reviewGrants`/`applyGrants`, and the one `registry_purpose` those
/// restricted profiles must accept in common. Profiles with no
/// `requiredPurposes` restriction do not require the claim.
fn reviewer_authority(authored: &Value, request: &Value) -> Result<ReviewerAuthority> {
    let profile_ids: BTreeSet<&str> = request["reviewGrants"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(request["applyGrants"].as_array().into_iter().flatten())
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
    for id in profile_ids {
        let profile = profiles
            .iter()
            .find(|candidate| candidate["id"] == id)
            .with_context(|| format!("BReg access profile {id} named by the selected request is absent from registry.yaml"))?;
        if profile["principalClaim"] != Value::String(READER_PRINCIPAL_CLAIM.to_owned()) {
            bail!("BReg access profile {id} does not authenticate its principal through {READER_PRINCIPAL_CLAIM}");
        }
        if has_nonempty_row_boundaries(profile) {
            bail!(
                "BReg access profile {id} uses rowBoundaries, which local Casework reviewer client export does not support"
            );
        }
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
    Ok(ReviewerAuthority { scopes, purpose })
}

fn has_nonempty_row_boundaries(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(has_nonempty_row_boundaries),
        Value::Object(values) => values.iter().any(|(key, value)| {
            if key == "rowBoundaries" {
                value
                    .as_array()
                    .is_none_or(|boundaries| !boundaries.is_empty())
            } else {
                has_nonempty_row_boundaries(value)
            }
        }),
        _ => false,
    }
}

/// The BReg dev client bound to one Casework dev client: same id and scopes
/// and claims, no access profile of its own. A staff or supervisor client
/// additionally carries the selected request's reviewer scopes, maps its
/// Casework principal into the BReg reviewer claim, and carries any required
/// purpose claim.
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
    let mut claims: BTreeMap<String, String> = client["claims"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
        .collect();
    if matches!(role, "staff" | "supervisor") {
        let authority = authority.context(
            "a Casework staff or supervisor dev client has no reviewer authority to bind",
        )?;
        let principal = claims
            .get(casework_principal_claim)
            .cloned()
            .with_context(|| {
                format!(
                    "Casework dev client {id} has no string value for its configured principal claim"
                )
            })?;
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
    Ok(json!({
        "id": id,
        "accessProfiles": Vec::<String>::new(),
        "scopes": scopes.into_iter().collect::<Vec<_>>(),
        "claims": claims,
    }))
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
    request: &Value,
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
        needs_authority |= matches!(role, "staff" | "supervisor");
        eligible.push((client, role.to_owned(), principal_claim.to_owned()));
    }
    let authority = if needs_authority {
        Some(reviewer_authority(authored, request)?)
    } else {
        None
    };
    let mut clients = vec![reader_dev_client()];
    for (client, role, principal_claim) in &eligible {
        clients.push(human_dev_client(
            client,
            role,
            principal_claim,
            authority.as_ref(),
        )?);
    }

    match fs::read(&dev_clients_path) {
        Ok(original) => {
            let mut authored_dev_clients: Value =
                serde_norway::from_slice(&original).context("parsing BReg dev-clients.yaml")?;
            let changes = apply_dev_clients_candidate(&mut authored_dev_clients, &clients)?;
            let proposed = render_dev_clients_preserving_authored_text(
                &original,
                &clients,
                &authored_dev_clients,
            )?;
            Ok(DevClientsPlan {
                patch: Value::Array(clients),
                changes,
                write: Some(DevClientsWrite {
                    path: dev_clients_path,
                    original,
                    proposed,
                }),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(absent_dev_clients_plan()),
        Err(error) => Err(error).context("reading BReg dev-clients.yaml"),
    }
}

fn absent_dev_clients_plan() -> DevClientsPlan {
    DevClientsPlan {
        patch: json!("absent"),
        changes: json!([]),
        write: None,
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
    Ok(Value::Array(changes))
}

fn render_dev_clients_preserving_authored_text(
    original: &[u8],
    clients: &[Value],
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
    let round_trip: Value =
        serde_norway::from_str(&rendered).context("parsing narrow BReg dev-clients YAML patch")?;
    if &round_trip != expected {
        bail!("narrow BReg dev-clients YAML patch changed unexpected authored content; no files were written");
    }
    Ok(rendered)
}

fn insert_dev_clients(text: &str, clients: &[&Value]) -> Result<String> {
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    let start = lines
        .iter()
        .position(|line| line.trim() == "clients:")
        .context("narrow YAML patch could not locate clients")?;
    let end = (start + 1..lines.len())
        .find(|index| {
            leading_spaces(lines[*index]) == 0
                && !lines[*index].trim().is_empty()
                && !lines[*index].trim_start().starts_with('#')
        })
        .unwrap_or(lines.len());
    let mut block = String::new();
    for client in clients {
        block.push_str(&render_dev_client_yaml_block(client)?);
    }
    Ok(insert_at_line(&lines, end, &block))
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
    request: SelectedRequest<'_>,
    report: &Value,
) -> Result<Value> {
    Ok(json!({
        "apiVersion":"registry.registrystack.org/casework-source-description/v1alpha1",
        "kind":"BRegCaseworkSourceDescription",
        "sourceId":source_id,
        "authority":"none",
        "origin":"bregctl explain change-requests",
        "sourceRevision":report["revision"],
        "request":request.0
    }))
}

fn runtime_binding(source_id: &str) -> String {
    format!("# Candidate BReg operator binding. Review and merge into the launcher-owned runtime config.\neventDestinations:\n  casework:\n    origin: http://localhost:8100\n    path: /events/sources/{source_id}\n    networkProfile: loopbackDevelopmentHttp\n    dnsFamily: ipv4Only\n    allowedPrivateCidrs: []\n    hmacSha256KeyRef: secret:file/breg-casework-webhook\n    classificationCeiling: restricted\n    deliveryCeilings:\n      attemptTimeoutMilliseconds: 5000\n      maximumAttempts: 5\n")
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

    #[test]
    fn source_import_preserves_multistage_approval_and_independence_requirements() {
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join("casework.yaml"), serde_json::to_vec(&json!({
            "sources": [{"id":"professional", "adapter":"breg", "requests":[{"entity":"correction"}]}]
        })).unwrap()).unwrap();
        let report = json!({"explanation":{"requests":[{
            "requestEntity":"correction", "reviewMode":"staged", "application":{"mode":"manual"},
            "stages":[
                {"id":"technical", "approvals":2, "excludeSubmitter":true, "excludePreviousReviewers":false},
                {"id":"authorization", "approvals":1, "excludeSubmitter":true, "excludePreviousReviewers":true}
            ]
        }]}});
        let selected = select_request(project.path(), "professional", &report).unwrap();
        assert_eq!(
            selected.0["stages"],
            report["explanation"]["requests"][0]["stages"]
        );
        let mut invalid = report;
        invalid["explanation"]["requests"][0]["stages"][0]["approvals"] = json!(0);
        assert!(select_request(project.path(), "professional", &invalid).is_err());
    }

    #[test]
    fn candidate_adds_only_exact_event_and_reader() {
        let mut root = json!({"entities":[{"id":"request"}],"accessProfiles":[]});
        apply_breg_candidate(&mut root, "request", &[]).unwrap();
        assert_eq!(
            root["entities"][0]["events"][0]["trigger"],
            "request_lifecycle"
        );
        assert_eq!(
            root["accessProfiles"][0]["grants"][0]["operations"],
            json!(["get", "list"])
        );
        assert_eq!(
            root["accessProfiles"][0]["grants"][0]["readableRequestFields"],
            json!(["review_state"])
        );
        apply_breg_candidate(&mut root, "request", &[]).unwrap();
        assert_eq!(root["entities"][0]["events"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn routing_projection_grants_only_declared_source_fields() {
        let project = tempfile::tempdir().unwrap();
        let write_policy = |projection: Value| {
            fs::write(
                project.path().join("casework.yaml"),
                serde_json::to_vec(&json!({
                    "sources":[{"id":"professional", "requests":[{"projection":projection}]}]
                }))
                .unwrap(),
            )
            .unwrap();
        };
        let metadata = json!({"fields":[{"field":"region","apiName":"region"}, {"field":"private-note","apiName":"privateNote"}]});
        write_policy(json!(["region"]));
        let projection = source_projection(project.path(), "professional", &metadata).unwrap();
        let input = "# keep authored context\nentities:\n  - id: request\n    route: requests\naccessProfiles: []\n";
        // The narrow YAML writer expects block-style accessProfiles, as documented.
        let input = input.replace("accessProfiles: []", "accessProfiles:");
        let mut expected =
            json!({"entities":[{"id":"request","route":"requests"}],"accessProfiles":[]});
        apply_breg_candidate(&mut expected, "request", &projection).unwrap();
        let rendered = render_candidate_preserving_authored_text(
            input.as_bytes(),
            "request",
            &expected,
            &projection,
        )
        .unwrap();
        assert!(rendered.contains("# keep authored context"));
        assert_eq!(
            expected["accessProfiles"][0]["grants"][0]["readableFields"],
            json!(["record", "region"])
        );
        assert_eq!(
            expected["entities"][0]["events"][0]["projection"],
            json!(["record"])
        );
        assert!(!rendered.contains("private-note"));
        write_policy(json!(["unknown"]));
        assert!(source_projection(project.path(), "professional", &metadata).is_err());
        write_policy(json!(["region", "region"]));
        assert!(source_projection(project.path(), "professional", &metadata).is_err());
    }

    #[test]
    fn candidate_refuses_conflicting_existing_grant() {
        let mut root = json!({"entities":[{"id":"request"}],"accessProfiles":[{"id":"casework-reader","grants":[]}]});
        assert!(apply_breg_candidate(&mut root, "request", &[]).is_err());
    }

    #[test]
    fn narrow_yaml_patch_preserves_comments() {
        let input = "# useful\nentities:\n  - id: request\n    route: requests\naccessProfiles:\n  - id: reader\n    # keep this\n    grants: []\n";
        let mut expected: Value = serde_norway::from_str(input).unwrap();
        apply_breg_candidate(&mut expected, "request", &[]).unwrap();
        let patched =
            render_candidate_preserving_authored_text(input.as_bytes(), "request", &expected, &[])
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
                "requiredScopes": ["starter:reviewer"],
                "requiredPurposes": ["starter-learning"]
            }]
        });
        let request = json!({
            "reviewGrants": [{"profile": "reviewer"}],
            "applyGrants": [{"profile": "reviewer"}]
        });
        (authored, request)
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
        let plan = plan_breg_dev_clients(registry.path(), &project, &authored, &request).unwrap();

        let clients = plan.patch.as_array().unwrap();
        let ids: Vec<&str> = clients.iter().map(|c| c["id"].as_str().unwrap()).collect();
        assert_eq!(
            ids,
            ["casework-reader", "administrator", "supervisor", "staff"]
        );

        let reader = clients
            .iter()
            .find(|c| c["id"] == "casework-reader")
            .unwrap();
        assert_eq!(reader["accessProfiles"], json!(["casework-reader"]));
        assert_eq!(reader["scopes"], json!(["casework:source-reader"]));
        assert_eq!(
            reader["claims"],
            json!({"registry_principal":"casework-reader","registry_purpose":"casework-sync"})
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
                {"file":"dev-clients.yaml","path":"/clients/staff","operation":"ensure_exact"}
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
        // The pre-existing client stays first; the four planned clients follow it.
        assert_eq!(
            written_ids,
            [
                "operator",
                "casework-reader",
                "administrator",
                "supervisor",
                "staff"
            ]
        );
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
        let plan = plan_breg_dev_clients(registry.path(), &project, &authored, &request).unwrap();
        let requester = plan
            .patch
            .as_array()
            .unwrap()
            .iter()
            .find(|client| client["id"] == "requester")
            .unwrap();
        assert_eq!(requester["accessProfiles"], json!([]));
        assert_eq!(requester["scopes"], json!(["casework:request"]));
        assert_eq!(requester["claims"], json!({}));
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
        let plan = plan_breg_dev_clients(registry.path(), &project, &authored, &request).unwrap();
        let clients = plan.patch.as_array().unwrap().clone();
        let mut expected: Value = serde_norway::from_str(input).unwrap();
        apply_dev_clients_candidate(&mut expected, &clients).unwrap();
        let write = plan.write.unwrap();
        assert!(write.proposed.contains("# operator callers"));
        assert!(write.proposed.contains("# do not rotate without notice"));
        assert_eq!(
            serde_norway::from_str::<Value>(&write.proposed).unwrap(),
            expected
        );
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
        let first = plan_breg_dev_clients(registry.path(), &project, &authored, &request).unwrap();
        let write = first.write.unwrap();
        write_atomic(&write.path, write.proposed.as_bytes()).unwrap();
        let second = plan_breg_dev_clients(registry.path(), &project, &authored, &request).unwrap();
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
        let error =
            plan_breg_dev_clients(registry.path(), &project, &authored, &request).unwrap_err();
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
        let plan = plan_breg_dev_clients(registry.path(), &project, &authored, &request).unwrap();
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
        let plan = plan_breg_dev_clients(registry.path(), &project, &authored, &request).unwrap();
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
        let plan = plan_breg_dev_clients(registry.path(), &project, &authored, &request).unwrap();
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
        let request = json!({"reviewGrants":[{"profile":"reviewer"}],"applyGrants":[]});
        assert!(reviewer_authority(&mismatched_principal, &request).is_err());

        let disagreeing_purpose = json!({
            "accessProfiles": [
                {"id":"reviewer","principalClaim":"registry_principal","requiredScopes":["starter:reviewer"],"requiredPurposes":["starter-learning"]},
                {"id":"approver","principalClaim":"registry_principal","requiredScopes":["starter:approver"],"requiredPurposes":["starter-approval"]}
            ]
        });
        let request =
            json!({"reviewGrants":[{"profile":"reviewer"}],"applyGrants":[{"profile":"approver"}]});
        assert!(reviewer_authority(&disagreeing_purpose, &request).is_err());
    }

    #[test]
    fn reviewer_authority_accepts_unrestricted_purpose_profiles() {
        let unrestricted = json!({
            "accessProfiles": [
                {"id":"reviewer","principalClaim":"registry_principal"},
                {"id":"approver","principalClaim":"registry_principal","requiredScopes":[],"requiredPurposes":[]}
            ]
        });
        let request =
            json!({"reviewGrants":[{"profile":"reviewer"}],"applyGrants":[{"profile":"approver"}]});
        let authority = reviewer_authority(&unrestricted, &request).unwrap();
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

    #[test]
    fn reviewer_authority_refuses_profiles_with_row_boundary_claims() {
        let authored = json!({
            "accessProfiles": [{
                "id":"reviewer",
                "principalClaim":"registry_principal",
                "grants":[{
                    "entity":"request",
                    "rowBoundaries":[{"field":"region","claim":"allowed_regions","operator":"in"}]
                }]
            }]
        });
        let request = json!({"reviewGrants":[{"profile":"reviewer"}],"applyGrants":[]});

        let error = reviewer_authority(&authored, &request)
            .err()
            .expect("row-boundary authority must be refused");
        let message = format!("{error:#}");
        assert!(message.contains("reviewer"), "{message}");
        assert!(message.contains("rowBoundaries"), "{message}");
        assert!(!message.contains("allowed_regions"), "{message}");
    }

    #[test]
    fn human_dev_client_bails_when_existing_purpose_claim_conflicts() {
        let authority = ReviewerAuthority {
            scopes: BTreeSet::from(["starter:reviewer".to_owned()]),
            purpose: Some("starter-learning".to_owned()),
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
            scopes: BTreeSet::from(["starter:reviewer".to_owned()]),
            purpose: None,
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
    fn human_dev_client_refuses_authority_over_breg_scope_or_claim_bounds() {
        let authority = ReviewerAuthority {
            scopes: BTreeSet::from(["starter:reviewer".to_owned()]),
            purpose: None,
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
                scopes: BTreeSet::new(),
                purpose: None,
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
}
