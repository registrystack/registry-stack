// SPDX-License-Identifier: Apache-2.0

use crate::SourceAddArgs;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_PROVIDER_OUTPUT: usize = 2 * 1024 * 1024;

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
    let description =
        source_description(&args.source_id, candidate_request, &candidate_explanation)?;
    let description_path = project
        .join("sources")
        .join(format!("{}.json", args.source_id));
    let binding_path = project
        .join("sources")
        .join(format!("{}.breg-runtime.yaml", args.source_id));
    let binding = runtime_binding(&args.source_id);
    let mut report = json!({
        "ok": true,
        "command": "source add",
        "status": if args.apply { "applied" } else { "preview" },
        "sourceId": args.source_id,
        "registry": registry,
        "project": project,
        "sourceDescription": description_path,
        "bregRuntimeBinding": binding_path,
        "bregAuthoringChanges": changes,
        "bregAuthoringPatch": {"event": event_patch, "accessProfile": reader_patch},
        "activation": "not_performed",
        "next": if args.apply {
            json!(["Review the generated BReg webhook binding and provision its secret reference. Configure the Casework source reader with the actual issuer tokenEndpoint, clientAssertionAudience, resource and scopes before activating through each product's normal path.", "Run caseworkctl doctor --runtime-config FILE after authenticated directory setup."])
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
        bail!(
            "BReg registry.yaml changed after preview; no files were written, retry source add against its current revision"
        );
    }
    fs::create_dir_all(description_path.parent().expect("source file has parent"))
        .context("creating Casework source directory")?;
    write_atomic(&registry_yaml, proposed.as_bytes())?;
    write_json_atomic(&description_path, &description)?;
    write_atomic(&binding_path, binding.as_bytes())?;
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
    match profiles.iter().find(|item| item["id"] == "casework-reader") {
        Some(existing) if existing != &profile => {
            bail!("BReg access profile casework-reader already exists with different content")
        }
        None => profiles.push(profile),
        _ => {}
    }
    Ok(json!([
        {"file":"registry.yaml","path":format!("/entities/{entity_id}/events/casework-lifecycle-v1"),"operation":"ensure_exact"},
        {"file":"registry.yaml","path":"/accessProfiles/casework-reader","operation":"ensure_exact"}
    ]))
}

fn candidate_fragments(entity_id: &str, projection: &[String]) -> (Value, Value) {
    let fields = reader_fields(projection);
    (
        json!({"id":"casework-lifecycle-v1","trigger":"request_lifecycle","projection":["record"],"webhook":{"destinationId":"casework"}}),
        json!({
            "id":"casework-reader", "default":false, "principalClaim":"registry_principal",
            "requiredScopes":["casework:source-reader"], "requiredPurposes":["casework-sync"],
            "permissions":[{"entity":entity_id,"operations":["get","list"],"readableFields":fields,"readableRequestFields":["review_state"],"rowBoundaries":[]}]
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
            .any(|profile| profile["id"] == "casework-reader")
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
        format!(
            "{}- id: casework-lifecycle-v1\n{}  trigger: request_lifecycle\n{}  projection: [record]\n{}  webhook: {{destinationId: casework}}\n",
            " ".repeat(field_indent + 2),
            " ".repeat(field_indent + 2),
            " ".repeat(field_indent + 2),
            " ".repeat(field_indent + 2)
        )
    } else {
        format!(
            "{}events:\n{}- id: casework-lifecycle-v1\n{}  trigger: request_lifecycle\n{}  projection: [record]\n{}  webhook: {{destinationId: casework}}\n",
            " ".repeat(field_indent),
            " ".repeat(field_indent + 2),
            " ".repeat(field_indent + 2),
            " ".repeat(field_indent + 2),
            " ".repeat(field_indent + 2)
        )
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
    let block = format!(
        "  - id: casework-reader\n    default: false\n    principalClaim: registry_principal\n    requiredScopes: [casework:source-reader]\n    requiredPurposes: [casework-sync]\n    permissions:\n      - entity: {entity_id}\n        operations: [get, list]\n        readableFields: {fields}\n        readableRequestFields: [review_state]\n        rowBoundaries: []\n"
    );
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
    format!(
        "# Candidate BReg operator binding. Review and merge into the launcher-owned runtime config.\neventDestinations:\n  casework:\n    origin: http://localhost:8100\n    path: /events/sources/{source_id}\n    networkProfile: loopbackDevelopmentHttp\n    dnsFamily: ipv4Only\n    allowedPrivateCidrs: []\n    hmacSha256KeyRef: secret:file/breg-casework-webhook\n    classificationCeiling: restricted\n    deliveryCeilings:\n      attemptTimeoutMilliseconds: 5000\n      maximumAttempts: 5\n"
    )
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
            root["accessProfiles"][0]["permissions"][0]["operations"],
            json!(["get", "list"])
        );
        assert_eq!(
            root["accessProfiles"][0]["permissions"][0]["readableRequestFields"],
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
            expected["accessProfiles"][0]["permissions"][0]["readableFields"],
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
        let mut root = json!({"entities":[{"id":"request"}],"accessProfiles":[{"id":"casework-reader","permissions":[]}]});
        assert!(apply_breg_candidate(&mut root, "request", &[]).is_err());
    }

    #[test]
    fn narrow_yaml_patch_preserves_comments() {
        let input = "# useful\nentities:\n  - id: request\n    route: requests\naccessProfiles:\n  - id: reader\n    # keep this\n    permissions: []\n";
        let mut expected: Value = serde_norway::from_str(input).unwrap();
        apply_breg_candidate(&mut expected, "request", &[]).unwrap();
        let patched =
            render_candidate_preserving_authored_text(input.as_bytes(), "request", &expected, &[])
                .unwrap();
        assert!(patched.contains("# useful"));
        assert!(patched.contains("# keep this"));
        assert_eq!(serde_norway::from_str::<Value>(&patched).unwrap(), expected);
    }
}
