// SPDX-License-Identifier: Apache-2.0
//! Explicit, policy-only successor preparation for a retained local registry.
use super::*;

#[derive(Debug, Args, Serialize)]
pub(super) struct PrepareSourceArgs {
    /// Existing registry project with a retained development session.
    #[arg(value_name = "PROJECT", default_value = ".")]
    project: PathBuf,
    /// Entity authored directly in registry.yaml; omit to inspect available fields.
    #[arg(long)]
    entity: Option<String>,
    /// Existing required scalar identifier with an exact single-field unique constraint.
    #[arg(long)]
    selector_field: Option<String>,
    /// Comma-separated selection of 1 to 16 readable fact fields; the identifier is also readable for identity verification.
    #[arg(long, value_delimiter = ',')]
    readable_fields: Vec<String>,
    /// Explicitly authorize lookup across all records of the selected entity.
    #[arg(long, conflicts_with = "row_field")]
    all_records: bool,
    /// Existing string, text or vocabulary-code field that bounds permitted records.
    #[arg(long, requires_all = ["row_claim", "row_value_file"])]
    row_field: Option<String>,
    /// Nonreserved direct claim name for the fixed local row boundary.
    #[arg(long, requires = "row_field")]
    row_claim: Option<String>,
    /// Owner-only input file containing a nonsecret scope label as a JSON string of 1 to 512 bytes; stored in dev-clients.yaml.
    #[arg(long, requires = "row_field")]
    row_value_file: Option<PathBuf>,
    /// Fresh dedicated local client ID; identical prepared requests reuse its credentials.
    #[arg(long, default_value = "evidence-source")]
    client: String,
    /// Fresh lookup-only access profile ID for the selected entity and facts.
    #[arg(long, default_value = "evidence-source")]
    access_profile: String,
    /// Fresh selector profile ID for the selected unique identifier.
    #[arg(long, default_value = "evidence-source")]
    selector_profile: String,
    /// Technical Evidence source identity used to validate the exact export.
    #[arg(long, default_value = "evidence-source")]
    source_id: String,
    /// Technical connection identity used to validate generated selector names.
    #[arg(long, default_value = "evidence-source")]
    connection: String,
    /// Prepare the reviewed successor and credential; next dev start activates it.
    #[arg(long)]
    #[serde(skip)]
    apply: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Transition {
    prior_digest: String,
    target_digest: String,
    sequence: u64,
    // Only the selected model document, registry identity, and clients change.
    originals: BTreeMap<PathBuf, Vec<u8>>,
    replacements: BTreeMap<PathBuf, Vec<u8>>,
    client: config::Client,
    clients: Clients,
    prepared: PreparedSource,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedSource {
    request_digest: String,
    report: Value,
}

fn request_digest(args: &PrepareSourceArgs) -> Result<String> {
    let mut request = serde_json::to_value(args)?;
    request["project"] = json!(project(&args.project)?);
    if let Some(path) = &args.row_value_file {
        request["row_value_file"] = json!(config::hash(&private::read(path, 4096)?));
    }
    Ok(config::hash(&serde_json::to_vec(&request)?))
}

fn scalar(field: &Value) -> bool {
    matches!(
        field["type"].as_str(),
        Some(
            "string"
                | "text"
                | "boolean"
                | "int64"
                | "decimal"
                | "date"
                | "timestamp"
                | "uuid"
                | "reference"
                | "vocabulary-code"
        )
    )
}
fn row_field(field: &Value) -> bool {
    matches!(
        field["type"].as_str(),
        Some("string" | "text" | "vocabulary-code")
    )
}
fn row_claim_name(claim: &str) -> bool {
    !claim.is_empty()
        && claim.len() <= 64
        && claim
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        && registry_breg::auth::valid_authority_claim_name(claim)
        && !["scope", "registry_principal", "registry_purpose"].contains(&claim)
}
fn identifier(entity: &Value, field: &Value) -> bool {
    scalar(field)
        && field["required"] == true
        && entity["constraints"].as_array().is_some_and(|constraints| {
            constraints
                .iter()
                .any(|c| c["kind"] == "unique" && c["fields"] == json!([field["id"]]))
        })
}
fn documents(files: &BTreeMap<String, Vec<u8>>) -> Result<BTreeMap<String, Value>> {
    files
        .iter()
        .filter(|(path, _)| *path == "registry.yaml" || path.ends_with("/module.yaml"))
        .map(|(path, bytes)| Ok((path.clone(), serde_norway::from_slice(bytes)?)))
        .collect()
}
fn inventory(docs: &BTreeMap<String, Value>, compiled: &registry_breg::CompiledRegistry) -> Value {
    json!(docs.get("registry.yaml").into_iter().flat_map(|doc| doc["entities"].as_array().into_iter().flatten()).filter(|entity| {
        entity["id"].as_str().and_then(|id|compiled.entities().get(id)).is_some_and(|entity|entity.change_request.is_none())
    }).map(|entity| {
        let fields = entity["fields"].as_array().cloned().unwrap_or_default();
        let supported = |field: &Value, selector: bool| {
            let Some(logical) = entity["id"].as_str().and_then(|id|compiled.entities().get(id)).and_then(|entity|entity.stored_fields.iter().find(|stored|Some(stored.logical.id.as_str()) == field["id"].as_str())).map(|field| &field.logical) else { return false; };
            let name = logical.id.as_bytes();
            let local_name = matches!(name.first(),Some(b'a'..=b'z')) && name.len() <= 64 && name.iter().all(|b|b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b,b'.'|b'_'|b'-'));
            local_name && scalar(field) && if selector {registry_breg::evidence_source::supports_selector_field(&logical.field_type)} else {registry_breg::evidence_source::supports_scalar_fact(&logical.field_type)}
        };
        let describe = |field: &Value| json!({"id":field["id"],"type":field["type"]});
        json!({"id":entity["id"],"selectorFields":fields.iter().filter(|field|identifier(entity,field) && supported(field,true)).map(describe).collect::<Vec<_>>(),
            "readableFields":fields.iter().filter(|field|supported(field,false)).map(describe).collect::<Vec<_>>(),
            "rowFields":fields.iter().filter(|field|row_field(field) && supported(field,false)).map(describe).collect::<Vec<_>>()})
    }).collect::<Vec<_>>())
}

pub(super) fn run(args: PrepareSourceArgs) -> Result<Value> {
    let project = project(&args.project)?;
    let parent = project.join(".breg");
    private::check(&parent, true)?;
    let _lock = private::lock(&parent.join("dev.lock"))?;
    let root = parent.join("dev");
    // A durable journal records the earlier explicit apply. Completing it
    // before inspection lets a consumer retry from the start after interruption.
    let recovered = recover(&root)?;
    let state = read_state(&root)?;
    let bytes =
        crate::read_bounded_source_file(&state.clients_file, "dev.clients", "clients", MAX_BYTES)
            .map_err(|_| anyhow::anyhow!("clients file is missing or unsafe"))?;
    let clients = config::clients(&bytes)?;
    let client_scopes: Vec<&String> = clients
        .clients
        .iter()
        .find(|client| client.id == "source")
        .map(|client| client.scopes.iter().collect())
        .unwrap_or_default();
    let captured = capture(&project, &bytes)?;
    if captured.digest != state.source_digest {
        bail!("authored inputs differ from the retained session; restore the recorded inputs before preparing a source. Arbitrary changes require the reviewed package lifecycle");
    }
    let mut docs = documents(&captured.files)?;
    let compiled = crate::compile(&project, crate::ProfileArg::Production, "prepare-source")
        .map_err(|_| anyhow::anyhow!("project no longer compiles"))?;
    let mut report = json!({"ok":true,"command":"dev prepare-source","project":project,"status":"inspect","recoveredPriorApply":recovered,
        "entities":inventory(&docs,&compiled),"bregUrl":state.breg_origin(),"issuer":state.issuer_origin(),"tokenEndpoint":format!("{}/oauth2/token",state.issuer_origin()),"clientAssertionAudience":state.issuer_origin(),"resource":state.audience(),"scopes":client_scopes,"audience":state.audience()});
    let Some(entity_id) = &args.entity else {
        if args.apply
            || args.selector_field.is_some()
            || !args.readable_fields.is_empty()
            || args.all_records
            || args.row_field.is_some()
        {
            bail!("select --entity, --selector-field, --readable-fields and explicit row authority to preview or apply");
        }
        return Ok(report);
    };
    let request_digest = request_digest(&args)?;
    let prepared_path = root.join(format!("source-prepared-{}.json", args.client));
    if config::identifier(&args.client) && prepared_path.exists() {
        let prepared: PreparedSource =
            serde_json::from_slice(&private::read(&prepared_path, MAX_BYTES)?)?;
        if prepared.request_digest != request_digest {
            bail!("selected source client already has different prepared authority; use fresh IDs for a separate source");
        }
        let mut report = prepared.report;
        report["requiresRestart"] = json!(!state.activated);
        report["recoveredPriorApply"] = json!(recovered);
        report["status"] = json!(if args.apply { "prepared" } else { "preview" });
        return Ok(report);
    }
    let _supervisor_lock = completed_supervisor_lock(&root, &state.status)?;
    if !matches!(state.status, Status::Stopped)
        || !state.activated
        || state.package_revision.is_none()
    {
        bail!("prepare-source requires a normally stopped, activated retained session; finish the pending dev start then stop it before adding a source");
    }
    for value in [&args.client, &args.access_profile, &args.selector_profile] {
        if !config::identifier(value) {
            bail!(
                "client, access profile and selector profile IDs must be bounded local identifiers"
            );
        }
    }
    let selector = args
        .selector_field
        .as_ref()
        .context("select --selector-field")?;
    if args.readable_fields.is_empty()
        || args.readable_fields.len() > 16
        || args.readable_fields.iter().collect::<BTreeSet<_>>().len() != args.readable_fields.len()
    {
        bail!("select 1..16 distinct --readable-fields explicitly");
    }
    if !args.all_records && args.row_field.is_none() {
        bail!("select --all-records or an explicit --row-field, --row-claim and --row-value-file binding");
    }
    let mut clients = config::clients(&bytes)?;
    if clients
        .clients
        .iter()
        .any(|c| c.id == args.client || c.access_profiles.contains(&args.access_profile))
    {
        bail!("dedicated client or access profile already exists; choose fresh IDs");
    }
    if docs.values().any(|doc| {
        doc["accessProfiles"]
            .as_array()
            .is_some_and(|profiles| profiles.iter().any(|p| p["id"] == args.access_profile))
    }) {
        bail!("access profile already exists; select a fresh dedicated profile ID");
    }
    let path = docs.iter().filter(|(path,_)|path.as_str() == "registry.yaml").find(|(_, doc)| doc["entities"].as_array().is_some_and(|entities|entities.iter().any(|e|e["id"] == *entity_id)))
        .map(|(path,_)|path.clone()).context("source preparation supports entities authored directly in registry.yaml; use the normal reviewed package lifecycle for module-owned entities")?;
    let entity = docs.get_mut(&path).unwrap()["entities"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["id"] == *entity_id)
        .unwrap();
    let fields = entity["fields"]
        .as_array()
        .context("selected entity has no fields")?;
    if !fields
        .iter()
        .any(|f| f["id"] == *selector && identifier(entity, f))
    {
        bail!("selector must be an existing required, bounded scalar field with an exact single-field unique constraint");
    }
    for id in &args.readable_fields {
        if !fields.iter().any(|f| f["id"] == *id && scalar(f)) {
            bail!("readable fields must name existing bounded scalar facts");
        }
    }
    let mut row_boundaries = vec![];
    let mut claims = BTreeMap::from([
        ("registry_principal".into(), json!(args.client)),
        ("registry_purpose".into(), json!("evidence-source-read")),
    ]);
    let row_scope = if let Some(field) = &args.row_field {
        let claim = args.row_claim.as_ref().context("row claim missing")?;
        if !row_claim_name(claim) {
            bail!("row claim must be a bounded nonreserved direct authority name");
        }
        if !fields.iter().any(|f| f["id"] == *field && row_field(f)) {
            bail!("local row scope requires an existing string, text or vocabulary-code field");
        }
        let value: Value = serde_json::from_slice(&private::read(
            args.row_value_file
                .as_ref()
                .context("row value file missing")?,
            4096,
        )?)
        .map_err(|_| anyhow::anyhow!("row value file must contain one JSON string"))?;
        if !value
            .as_str()
            .is_some_and(|value| !value.is_empty() && value.len() <= 512)
        {
            bail!("local row value must be a JSON string of 1..512 bytes");
        }
        let logical = compiled
            .entities()
            .get(entity_id)
            .and_then(|entity| {
                entity
                    .stored_fields
                    .iter()
                    .find(|stored| stored.logical.id == *field)
            })
            .context("row field is absent from the compiled model")?;
        if !registry_breg::auth::valid_direct_scalar_claim(&value, &logical.logical.field_type) {
            bail!("local row value does not satisfy the selected field type and bounds");
        }
        claims.insert(claim.clone(), value);
        row_boundaries.push(json!({"field":field,"claim":claim,"operator":"equals"}));
        json!({"kind":"claim","field":field,"claim":claim})
    } else {
        json!({"kind":"all-records"})
    };
    if entity["selectorProfiles"].is_null() {
        entity["selectorProfiles"] = json!([]);
    }
    let selectors = entity["selectorProfiles"]
        .as_array_mut()
        .context("selector profiles must be an array")?;
    if selectors.iter().any(|s| s["id"] == args.selector_profile) {
        bail!("selector profile already exists; choose a fresh ID");
    }
    selectors.push(json!({"id":args.selector_profile,"fields":[selector]}));
    let registry = docs
        .get_mut("registry.yaml")
        .context("registry document missing")?;
    let scope = format!("registry:{}:lookup", args.client);
    let mut grant_fields = args.readable_fields.clone();
    if !grant_fields.contains(selector) {
        grant_fields.push(selector.clone());
    }
    if registry["accessProfiles"].is_null() {
        registry["accessProfiles"] = json!([]);
    }
    registry["accessProfiles"].as_array_mut().context("access profiles missing")?.push(json!({
        "id":args.access_profile,"principalClaim":"registry_principal","requiredScopes":[scope],"requiredPurposes":["evidence-source-read"],
        "permissions":[{"entity":entity_id,"operations":["lookup"],"readableFields":grant_fields,
            "lookups":[{"selector":args.selector_profile,"valueOrigin":"request"}],"rowBoundaries":row_boundaries}]}));
    let sequence = state
        .sequence
        .checked_add(1)
        .context("package sequence exhausted")?;
    registry["package"]["sequence"] = json!(sequence);
    let client = config::Client {
        id: args.client.clone(),
        access_profiles: vec![args.access_profile.clone()],
        allow_breg_access: false,
        scopes: vec![scope],
        claims,
        test_bindings: Vec::new(),
        client_id_file: None,
        assertion_key_file: None,
    };
    clients.clients.push(client.clone());
    let client_bytes = yaml_with_comments(&serde_json::to_value(&clients)?, &bytes)?;
    config::clients(&client_bytes)?;
    let candidate = root.join(format!(".source-preview-{}", uuid::Uuid::new_v4()));
    private::directory(&candidate)?;
    let result = (|| {
        let mut replacements = BTreeMap::new();
        for (relative, original) in &captured.files {
            let bytes = if relative == "registry.yaml" || relative == &path {
                yaml_with_comments(&docs[relative], original)?
            } else {
                original.clone()
            };
            write_captured(&candidate, relative, &bytes)?;
            if bytes != *original {
                replacements.insert(project.join(relative), bytes);
            }
        }
        let previous = crate::compile(
            &root.join("project"),
            crate::ProfileArg::Production,
            "prepare-source",
        )
        .map_err(|_| anyhow::anyhow!("retained source failed compilation"))?;
        let compiled = crate::compile(&candidate, crate::ProfileArg::Production, "prepare-source")
            .map_err(|failure| {
                anyhow::anyhow!(
                    "selected source authority does not compile: {}",
                    serde_json::to_string(&failure).unwrap_or_default()
                )
            })?;
        registry_breg::authority::authority_inventory(&compiled).map_err(|error| {
            anyhow::anyhow!("selected source authority is incompatible: {error}")
        })?;
        registry_breg::evidence_source::export_evidence_source(
            &compiled,
            &registry_breg::evidence_source::EvidenceSourceOptions {
                access_profile: args.access_profile.clone(),
                entity: entity_id.clone(),
                selectors: vec![args.selector_profile.clone()],
                fields: args.readable_fields.clone(),
                source_id: args.source_id.clone(),
                connection: args.connection.clone(),
            },
        )
        .map_err(|diagnostic| {
            anyhow::anyhow!("selected source cannot be exported: {}", diagnostic.message)
        })?;
        let changes = registry_breg::package::compiled_registry_change_set(
            &previous,
            &compiled,
            state.package_revision.as_deref().unwrap(),
        );
        let plan = registry_breg::package::change_set_to_applicable_migration_plan(&changes)
            .with_context(|| {
                format!(
                    "selected source requires an unsupported schema migration: {}",
                    serde_json::to_string(&changes).unwrap_or_default()
                )
            })?;
        // A selector backed by existing uniqueness must change no storage DDL.
        ensure_policy_only(&plan)?;
        let target = capture(&candidate, &client_bytes)?;
        replacements.insert(state.clients_file.clone(), client_bytes);
        report["status"] = json!(if args.apply { "prepared" } else { "preview" });
        for (key, value) in [
            ("entity", json!(entity_id)),
            ("selectorField", json!(selector)),
            ("selectorProfile", json!(args.selector_profile)),
            ("accessProfile", json!(args.access_profile)),
            ("client", json!(args.client)),
            ("preparedClientScopes", json!(&client.scopes)),
            ("readableFields", json!(args.readable_fields)),
            ("rowScope", row_scope),
            ("packageSequence", json!(sequence)),
            ("changeSet", serde_json::to_value(&changes)?),
            ("requiresRestart", json!(true)),
        ] {
            report[key] = value;
        }
        if args.apply {
            let originals = replacements.keys().map(|path| {
                let expected = if path == &state.clients_file { bytes.clone() } else {
                    captured.files[path.strip_prefix(&project)?.to_str().context("source path must be UTF-8")?].clone()
                };
                if read_authoring(path)? != expected { bail!("authoring changed during source preview; inspect the changes and retry"); }
                Ok((path.clone(),expected))
            }).collect::<Result<_>>()?;
            let transition = Transition {
                prior_digest: state.source_digest.clone(),
                target_digest: target.digest,
                sequence,
                originals,
                replacements,
                client,
                clients,
                prepared: PreparedSource {
                    request_digest,
                    report: report.clone(),
                },
            };
            let journal = serde_json::to_vec(&transition)?;
            if journal.len() as u64 > MAX_BYTES {
                bail!("source transition exceeds the retained journal size bound");
            }
            private::replace(&root.join("source-transition.json"), &journal)?;
            finish(&state, &transition)?;
        }
        Ok(report)
    })();
    fs::remove_dir_all(candidate)?;
    result
}

fn ensure_policy_only(plan: &registry_breg::package::MigrationPlan) -> Result<()> {
    if !plan.statements.is_empty() {
        bail!("source preparation requires a policy-only successor with no storage DDL");
    }
    Ok(())
}
fn write_captured(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    let path = root.join(relative);
    let mut directory = root.to_path_buf();
    for component in path
        .parent()
        .context("source parent missing")?
        .strip_prefix(root)?
        .components()
    {
        directory.push(component);
        private::directory(&directory)?;
    }
    private::replace(&path, bytes)
}

pub(super) fn recover(root: &Path) -> Result<bool> {
    let journal = root.join("source-transition.json");
    if !journal.exists() {
        return Ok(false);
    }
    let state = read_state(root)?;
    let _supervisor_lock = completed_supervisor_lock(root, &state.status)?;
    let transition: Transition = serde_json::from_slice(&private::read(&journal, MAX_BYTES)?)?;
    finish(&state, &transition)?;
    Ok(true)
}
fn finish(original: &State, transition: &Transition) -> Result<()> {
    let root = original.root();
    if original.source_digest != transition.prior_digest
        && original.source_digest != transition.target_digest
    {
        bail!("source preparation journal does not match retained state");
    }
    for (path, bytes) in &transition.replacements {
        let current = read_authoring(path)?;
        if current != *bytes && Some(&current) != transition.originals.get(path) {
            bail!("prepared source input changed; restore the previewed input before retrying");
        }
    }
    let baseline = root.join(format!("baseline-{}", transition.sequence - 1));
    private::directory(&baseline)?;
    if !baseline.join("build").exists() {
        fs::rename(root.join("build"), baseline.join("build"))?;
    }
    if !baseline.join("runtime.yaml").exists() {
        let mut runtime: Value =
            serde_norway::from_slice(&private::read(&root.join("runtime.yaml"), MAX_BYTES)?)?;
        runtime["package"]["root"] = json!(baseline.join("build/package"));
        private::replace(
            &baseline.join("runtime.yaml"),
            serde_norway::to_string(&runtime)?.as_bytes(),
        )?;
    }
    let credential = root.join("credentials").join(&transition.client.id);
    if !credential.exists() {
        let staging = root
            .join("credentials")
            .join(format!(".source-{}", uuid::Uuid::new_v4()));
        config::keypair(&staging)?;
        private::create(&staging.join("client-id"), transition.client.id.as_bytes())?;
        File::open(&staging)?.sync_all()?;
        fs::rename(staging, &credential)?;
        File::open(root.join("credentials"))?.sync_all()?;
    }
    // The reviewed successor adds a native machine agent, role, and resource
    // permission for this lookup-only client. Publish the whole derived issuer
    // description so the next owned restart bootstraps the registration.
    config::refresh_issuer_registration(original, &transition.clients)?;
    for (path, bytes) in &transition.replacements {
        // Authoring files are ordinary project files, not private state. The
        // source capture checked their safety; no unrelated file is replaced.
        replace_authoring(path, bytes)?;
        if path != &original.clients_file {
            write_captured(
                &root.join("project"),
                path.strip_prefix(&original.project)?
                    .to_str()
                    .context("source path is not UTF-8")?,
                bytes,
            )?;
        }
    }
    private::replace(
        &root.join("clients.json"),
        &serde_json::to_vec(&transition.clients)?,
    )?;
    let mut state = original.clone();
    state.sequence = transition.sequence;
    state.baseline_runtime = Some(baseline.join("runtime.yaml"));
    state.source_digest = transition.target_digest.clone();
    state.package_revision = None;
    state.activated = false;
    if root.join("runtime-test.yaml").exists() {
        fs::remove_file(root.join("runtime-test.yaml"))?;
    }
    config::runtime(
        &root,
        &state,
        &transition.clients,
        &format!("sha256:{}", "1".repeat(64)),
        true,
    )?;
    state.save()?;
    private::replace(
        &root.join(format!("source-prepared-{}.json", transition.client.id)),
        &serde_json::to_vec(&transition.prepared)?,
    )?;
    fs::remove_file(root.join("source-transition.json"))?;
    Ok(())
}

/// Keep full-line author notes with their top-level section while normalizing
/// the changed YAML. This does not pretend to preserve arbitrary YAML layout.
fn yaml_with_comments(value: &Value, original: &[u8]) -> Result<Vec<u8>> {
    let object = value
        .as_object()
        .context("source document must be a mapping")?;
    let section = |line: &str| {
        object
            .keys()
            .find(|key| line.starts_with(&format!("{key}:")))
            .cloned()
    };
    let mut notes = BTreeMap::<String, Vec<String>>::new();
    let mut header = vec![];
    let mut pending = vec![];
    let mut current = None;
    let mut content_seen = false;
    for line in std::str::from_utf8(original)?.lines() {
        if line.trim().starts_with('#') {
            if content_seen {
                pending.push(line.trim_start().to_owned());
            } else {
                header.push(line.to_owned());
            }
        } else if !line.trim().is_empty() {
            content_seen = true;
            if let Some(key) = section(line) {
                current = Some(key);
            }
            if let Some(key) = &current {
                notes.entry(key.clone()).or_default().append(&mut pending);
            } else {
                header.append(&mut pending);
            }
        }
    }
    if let Some(key) = current {
        notes.entry(key).or_default().append(&mut pending);
    } else {
        header.append(&mut pending);
    }
    let mut output = String::new();
    for line in header {
        output.push_str(&line);
        output.push('\n');
    }
    for line in serde_norway::to_string(value)?.lines() {
        if let Some(key) = section(line) {
            if let Some(comments) = notes.remove(&key) {
                for comment in comments {
                    output.push_str(&comment);
                    output.push('\n');
                }
            }
        }
        output.push_str(line);
        output.push('\n');
    }
    Ok(output.into_bytes())
}

fn read_authoring(path: &Path) -> Result<Vec<u8>> {
    crate::read_bounded_source_file(path, "dev.prepare-source", "authoring", MAX_BYTES).map_err(
        |_| {
            anyhow::anyhow!(
                "source preparation requires unchanged bounded ordinary authoring files"
            )
        },
    )
}
fn replace_authoring(path: &Path, bytes: &[u8]) -> Result<()> {
    use crate::safe_path::{SafeEntry, SafePathError};
    let entry = SafeEntry::resolve(path).map_err(SafePathError::into_io)?;
    let current = entry.open_read()?;
    let metadata = current.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        bail!("source preparation requires an ordinary single-link authoring file");
    }
    let temporary = std::ffi::OsString::from(format!(".source-{}", uuid::Uuid::new_v4()));
    let mut output = entry
        .parent()
        .create_new(&temporary, metadata.permissions().mode() & 0o777)?;
    let result = (|| {
        output.write_all(bytes)?;
        output.sync_all()?;
        entry.parent().rename(&temporary, entry.name())?;
        entry.parent().sync()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = entry.parent().remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source_fixture() -> (tempfile::TempDir, State) {
        source_fixture_with_top_level_profiles(true)
    }
    fn source_fixture_with_top_level_profiles(top_level: bool) -> (tempfile::TempDir, State) {
        let (temporary, mut state, mut clients, _) = super::super::tests::fixture();
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/evidence/registry");
        let mut model: Value =
            serde_norway::from_slice(&fs::read(fixture.join("registry.yaml")).unwrap()).unwrap();
        model["entities"][0]
            .as_object_mut()
            .unwrap()
            .remove("selectorProfiles");
        model["accessProfiles"].as_array_mut().unwrap().truncate(1);
        if !top_level {
            let mut profiles = model
                .as_object_mut()
                .unwrap()
                .remove("accessProfiles")
                .unwrap();
            let mut operator = profiles.as_array_mut().unwrap().remove(0);
            let mut permissions = operator
                .as_object_mut()
                .unwrap()
                .remove("permissions")
                .unwrap();
            let mut permission = permissions.as_array_mut().unwrap().remove(0);
            permission.as_object_mut().unwrap().remove("entity");
            operator
                .as_object_mut()
                .unwrap()
                .extend(permission.as_object().unwrap().clone());
            let module = json!({"id":"local-authority","version":"1","extendEntities":[{"entity":"record","accessProfiles":[operator]}]});
            let module_bytes = serde_norway::to_string(&module).unwrap().into_bytes();
            let parsed = registry_breg::contract::parse_module_yaml(&module_bytes).unwrap();
            model["modules"] = json!([{"id":"local-authority","version":"1","digest":registry_breg::compiler::module_digest(&parsed)}]);
            let directory = state.project.join("modules/local-authority");
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("module.yaml"), module_bytes).unwrap();
        }
        clients.clients.truncate(1);
        clients.clients[0]
            .claims
            .insert("registry_purpose".into(), json!("registry-operations"));
        let client_bytes = serde_norway::to_string(&clients).unwrap().into_bytes();
        fs::write(&state.clients_file, &client_bytes).unwrap();
        fs::create_dir_all(state.project.join("tests")).unwrap();
        fs::write(
            state.project.join("registry.yaml"),
            serde_norway::to_string(&model).unwrap(),
        )
        .unwrap();
        fs::copy(
            fixture.join("tests/journeys.yaml"),
            state.project.join("tests/journeys.yaml"),
        )
        .unwrap();
        crate::compile(
            &state.project,
            crate::ProfileArg::Production,
            "prepare-source",
        )
        .unwrap_or_else(|failure| {
            panic!(
                "fixture must compile: {}",
                serde_json::to_string(&failure).unwrap()
            )
        });
        let capture = capture(&state.project, &client_bytes).unwrap();
        state.source_digest = capture.digest;
        state.instance_id = capture.instance_id;
        state.source_revision = capture.source_revision;
        state.package_revision = Some(format!("sha256:{}", "a".repeat(64)));
        state.activated = true;
        initialize(&state.root(), &state, &clients, &capture.files).unwrap();
        (temporary, state)
    }
    fn args(state: &State) -> PrepareSourceArgs {
        PrepareSourceArgs {
            project: state.project.clone(),
            entity: Some("record".into()),
            selector_field: Some("code".into()),
            readable_fields: vec!["label".into()],
            all_records: true,
            row_field: None,
            row_claim: None,
            row_value_file: None,
            client: "source-reader".into(),
            access_profile: "source-reader".into(),
            selector_profile: "by-code".into(),
            source_id: "registry".into(),
            connection: "registry".into(),
            apply: false,
        }
    }
    #[test]
    fn existing_unique_selector_and_lookup_grant_are_a_zero_ddl_successor() {
        let (_temporary, state) = source_fixture();
        let before = fs::read(state.project.join("registry.yaml")).unwrap();
        let report = run(args(&state)).unwrap();
        assert_eq!(report["packageSequence"], 2);
        assert_eq!(report["readableFields"], json!(["label"]));
        assert_eq!(
            report["changeSet"]["migrationPlan"]["statements"],
            json!([])
        );
        assert_eq!(
            fs::read(state.project.join("registry.yaml")).unwrap(),
            before
        );
    }
    #[test]
    fn preparation_adds_the_optional_top_level_profiles_without_changing_module_authority() {
        let (_temporary, state) = source_fixture_with_top_level_profiles(false);
        let path = state.project.join("registry.yaml");
        let before = fs::read(&path).unwrap();
        let original: Value = serde_norway::from_slice(&before).unwrap();
        assert!(original.get("accessProfiles").is_none());
        let module_path = state.project.join("modules/local-authority/module.yaml");
        let module_bytes = fs::read(&module_path).unwrap();
        let previous = crate::compile(
            &state.project,
            crate::ProfileArg::Production,
            "prepare-source",
        )
        .unwrap_or_else(|failure| panic!("{}", serde_json::to_string(&failure).unwrap()));
        let preview = run(args(&state)).unwrap();
        assert_eq!(preview["packageSequence"], 2);
        assert_eq!(
            preview["preparedClientScopes"],
            json!(["registry:source-reader:lookup"])
        );
        assert_eq!(preview["resource"], preview["audience"]);
        assert_eq!(preview["clientAssertionAudience"], preview["issuer"]);
        assert_eq!(
            preview["changeSet"]["migrationPlan"]["statements"],
            json!([])
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        let root = state.root();
        private::directory(&root.join("build")).unwrap();
        private::directory(&root.join("build/package")).unwrap();
        let clients: Clients =
            serde_json::from_slice(&private::read(&root.join("clients.json"), MAX_BYTES).unwrap())
                .unwrap();
        config::runtime(
            &root,
            &state,
            &clients,
            state.package_revision.as_deref().unwrap(),
            false,
        )
        .unwrap();
        let mut selected = args(&state);
        selected.apply = true;
        let applied = run(selected).unwrap();
        assert_eq!(applied["status"], "prepared");
        assert_eq!(
            applied["preparedClientScopes"],
            preview["preparedClientScopes"]
        );
        let agents = root.join("issuer/registry-schema/agents");
        let registrations: Vec<Value> = fs::read_dir(&agents)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                serde_norway::from_slice(&private::read(&entry.path(), MAX_BYTES).unwrap()).unwrap()
            })
            .collect();
        let source = registrations
            .iter()
            .find(|agent| agent["inboundAuthConfig"][0]["config"]["clientId"] == "source-reader")
            .expect("the prepared source has a native machine registration");
        assert_eq!(source["attributes"]["registry_principal"], "source-reader");
        assert!(!root.join("mint/clients/source-reader.yaml").exists());
        let roles = root.join("issuer/resources/roles");
        let grants: Vec<Value> = fs::read_dir(roles)
            .unwrap()
            .map(|entry| {
                serde_norway::from_slice(&private::read(&entry.unwrap().path(), MAX_BYTES).unwrap())
                    .unwrap()
            })
            .collect();
        assert!(grants
            .iter()
            .any(|role| role["permissions"][0]["permissions"]
                == json!(["registry:source-reader:lookup"])));
        let prepared: Value = serde_norway::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(prepared["accessProfiles"].as_array().unwrap().len(), 1);
        assert_eq!(prepared["accessProfiles"][0]["id"], "source-reader");
        assert_eq!(prepared["modules"], original["modules"]);
        assert_eq!(fs::read(module_path).unwrap(), module_bytes);
        let candidate = crate::compile(
            &state.project,
            crate::ProfileArg::Production,
            "prepare-source",
        )
        .unwrap_or_else(|failure| panic!("{}", serde_json::to_string(&failure).unwrap()));
        assert_eq!(
            candidate.entities()["record"].access_profiles["operator"],
            previous.entities()["record"].access_profiles["operator"]
        );
    }

    #[test]
    fn preparation_retries_preserve_keys_seed_checkpoints_and_exact_source_recovery() {
        let (_temporary, mut state) = source_fixture();
        state.seeded.insert("record-created".into());
        state.save().unwrap();
        let root = state.root();
        private::directory(&root.join("build")).unwrap();
        private::directory(&root.join("build/package")).unwrap();
        let old_clients: Clients =
            serde_json::from_slice(&private::read(&root.join("clients.json"), MAX_BYTES).unwrap())
                .unwrap();
        config::runtime(
            &root,
            &state,
            &old_clients,
            state.package_revision.as_deref().unwrap(),
            false,
        )
        .unwrap();
        let operator_path = root.join("credentials/operator/assertion-key.jwk");
        let operator = private::read(&operator_path, MAX_BYTES).unwrap();
        let originals = BTreeMap::from([
            (
                state.project.join("registry.yaml"),
                fs::read(state.project.join("registry.yaml")).unwrap(),
            ),
            (
                state.clients_file.clone(),
                fs::read(&state.clients_file).unwrap(),
            ),
        ]);
        let mut selected = args(&state);
        selected.apply = true;
        let first = run(selected).unwrap();
        let pending = read_state(&root).unwrap();
        assert_eq!(pending.sequence, 2);
        assert_eq!(pending.seeded, state.seeded);
        assert!(!pending.activated);
        assert_eq!(private::read(&operator_path, MAX_BYTES).unwrap(), operator);
        let key_path = root.join("credentials/source-reader/assertion-key.jwk");
        let key = private::read(&key_path, MAX_BYTES).unwrap();
        let mut selected = args(&state);
        selected.apply = true;
        assert_eq!(run(selected).unwrap(), first);
        assert_eq!(private::read(&key_path, MAX_BYTES).unwrap(), key);
        let prepared: PreparedSource = serde_json::from_slice(
            &private::read(&root.join("source-prepared-source-reader.json"), MAX_BYTES).unwrap(),
        )
        .unwrap();
        let clients: Clients =
            serde_json::from_slice(&private::read(&root.join("clients.json"), MAX_BYTES).unwrap())
                .unwrap();
        let replacements = originals
            .keys()
            .map(|path| (path.clone(), fs::read(path).unwrap()))
            .collect();
        let transition = Transition {
            prior_digest: state.source_digest.clone(),
            target_digest: pending.source_digest.clone(),
            sequence: 2,
            originals: originals.clone(),
            replacements,
            client: clients.clients.last().unwrap().clone(),
            clients,
            prepared,
        };
        // Emulate an interruption after one authored replacement. Recovery must
        // accept only these complete before/after files and reuse the new key.
        state.save().unwrap();
        replace_authoring(
            &state.project.join("registry.yaml"),
            &originals[&state.project.join("registry.yaml")],
        )
        .unwrap();
        private::create(
            &root.join("source-transition.json"),
            &serde_json::to_vec(&transition).unwrap(),
        )
        .unwrap();
        replace_authoring(
            &state.project.join("registry.yaml"),
            b"unrelated interrupted edit",
        )
        .unwrap();
        assert!(recover(&root)
            .unwrap_err()
            .to_string()
            .contains("input changed"));
        replace_authoring(
            &state.project.join("registry.yaml"),
            &originals[&state.project.join("registry.yaml")],
        )
        .unwrap();
        recover(&root).unwrap();
        assert_eq!(
            read_state(&root).unwrap().source_digest,
            pending.source_digest
        );
        assert_eq!(private::read(&key_path, MAX_BYTES).unwrap(), key);
        assert!(!root.join("source-transition.json").exists());
        let mut changed = args(&state);
        changed.readable_fields.push("status".into());
        assert!(run(changed)
            .unwrap_err()
            .to_string()
            .contains("different prepared authority"));
    }

    #[test]
    fn explicit_row_binding_is_private_and_does_not_expand_selected_facts() {
        let (_temporary, state) = source_fixture();
        let claim = state.root().join("row-claim.json");
        private::create(&claim, br#""private-row-value-canary""#).unwrap();
        let mut selected = args(&state);
        selected.all_records = false;
        selected.row_field = Some("label".into());
        selected.row_claim = Some("source_label".into());
        selected.row_value_file = Some(claim);
        let report = run(selected).unwrap();
        assert_eq!(
            report["rowScope"],
            json!({"kind":"claim","field":"label","claim":"source_label"})
        );
        assert_eq!(report["readableFields"], json!(["label"]));
        assert!(!report.to_string().contains("private-row-value-canary"));
    }

    #[test]
    fn unexportable_selection_is_refused_before_preparing_authority() {
        let (_temporary, mut state) = source_fixture();
        let path = state.project.join("registry.yaml");
        let mut model: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
        model["entities"][0]["fields"][0]["minLength"] = json!(0);
        let bytes = serde_norway::to_string(&model).unwrap().into_bytes();
        fs::write(&path, &bytes).unwrap();
        private::replace(&state.root().join("project/registry.yaml"), &bytes).unwrap();
        state.source_digest = capture(&state.project, &fs::read(&state.clients_file).unwrap())
            .unwrap()
            .digest;
        state.save().unwrap();
        let mut inspect = args(&state);
        inspect.entity = None;
        inspect.selector_field = None;
        inspect.readable_fields.clear();
        inspect.all_records = false;
        let inventory = run(inspect).unwrap();
        assert!(!inventory["entities"][0]["selectorFields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field["id"] == "code"));
        let mut selected = args(&state);
        selected.apply = true;
        assert!(run(selected)
            .unwrap_err()
            .to_string()
            .contains("cannot be exported"));
        assert_eq!(fs::read(path).unwrap(), bytes);
        assert!(!state.root().join("source-transition.json").exists());
        assert!(!state.root().join("credentials/source-reader").exists());
    }

    #[test]
    fn invalid_mint_or_field_row_claims_leave_authoring_and_keys_unchanged() {
        let (_temporary, state) = source_fixture();
        let root = state.root();
        let model = fs::read(state.project.join("registry.yaml")).unwrap();
        let retained = private::read(&root.join("state.json"), MAX_BYTES).unwrap();
        let operator = private::read(
            &root.join("credentials/operator/assertion-key.jwk"),
            MAX_BYTES,
        )
        .unwrap();
        let value_file = root.join("row-value.json");
        let registered_claims = [
            "iss",
            "aud",
            "exp",
            "iat",
            "nbf",
            "sub",
            "client_id",
            "azp",
            "jti",
            "cnf",
        ];
        let cases = registered_claims
            .into_iter()
            .map(|claim| (claim, "label", json!("allowed")))
            .chain([
                ("scope", "label", json!("allowed")),
                ("registry_principal", "label", json!("allowed")),
                ("registry_purpose", "label", json!("allowed")),
                ("bad claim", "label", json!("allowed")),
                ("row_label", "label", json!(true)),
                ("row_label", "label", json!("x".repeat(513))),
                ("row_label", "label", json!("x".repeat(101))),
                ("row_status", "status", json!("unlisted-value-canary")),
            ]);
        for (claim, field, value) in cases {
            private::replace(&value_file, &serde_json::to_vec(&value).unwrap()).unwrap();
            let mut selected = args(&state);
            selected.apply = true;
            selected.all_records = false;
            selected.row_field = Some(field.into());
            selected.row_claim = Some(claim.into());
            selected.row_value_file = Some(value_file.clone());
            assert!(run(selected).is_err());
            assert_eq!(
                fs::read(state.project.join("registry.yaml")).unwrap(),
                model
            );
            assert_eq!(
                private::read(&root.join("state.json"), MAX_BYTES).unwrap(),
                retained
            );
            assert_eq!(
                private::read(
                    &root.join("credentials/operator/assertion-key.jwk"),
                    MAX_BYTES
                )
                .unwrap(),
                operator
            );
            assert!(!root.join("source-transition.json").exists());
            assert!(!root.join("credentials/source-reader").exists());
        }
    }

    #[test]
    fn conflicting_existing_claim_shapes_are_refused_before_preparing_authority() {
        for (field, operator) in [("code", "equals"), ("label", "in")] {
            let (_temporary, mut state) = source_fixture();
            let root = state.root();
            let path = state.project.join("registry.yaml");
            let mut model: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
            model["accessProfiles"][0]["permissions"][0]["rowBoundaries"] =
                json!([{"field":field,"claim":"existing_row","operator":operator}]);
            let model = serde_norway::to_string(&model).unwrap().into_bytes();
            fs::write(&path, &model).unwrap();
            private::replace(&root.join("project/registry.yaml"), &model).unwrap();
            let clients = fs::read(&state.clients_file).unwrap();
            state.source_digest = capture(&state.project, &clients).unwrap().digest;
            state.save().unwrap();
            let compiled = crate::compile(
                &state.project,
                crate::ProfileArg::Production,
                "prepare-source",
            )
            .unwrap_or_else(|failure| panic!("{}", serde_json::to_string(&failure).unwrap()));
            registry_breg::authority::authority_inventory(&compiled).unwrap();
            let retained = private::read(&root.join("state.json"), MAX_BYTES).unwrap();
            let key_path = root.join("credentials/operator/assertion-key.jwk");
            let key = private::read(&key_path, MAX_BYTES).unwrap();
            let row_value = root.join("row-value.json");
            private::create(&row_value, b"\"allowed\"").unwrap();
            let mut selected = args(&state);
            selected.apply = true;
            selected.all_records = false;
            selected.row_field = Some("label".into());
            selected.row_claim = Some("existing_row".into());
            selected.row_value_file = Some(row_value);
            assert!(run(selected)
                .unwrap_err()
                .to_string()
                .contains("different value shapes"));
            assert_eq!(fs::read(&path).unwrap(), model);
            assert_eq!(fs::read(&state.clients_file).unwrap(), clients);
            assert_eq!(
                private::read(&root.join("state.json"), MAX_BYTES).unwrap(),
                retained
            );
            assert_eq!(private::read(&key_path, MAX_BYTES).unwrap(), key);
            assert!(!root.join("source-transition.json").exists());
            assert!(!root.join("credentials/source-reader").exists());
        }
    }

    #[test]
    fn required_unique_references_are_offered_prepared_and_exported_without_row_scope_expansion() {
        let (_temporary, mut state) = source_fixture();
        let path = state.project.join("registry.yaml");
        let mut model: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut target = model["entities"][0].clone();
        target["id"] = json!("organization");
        target["route"] = json!("organizations");
        model["entities"].as_array_mut().unwrap().push(target);
        let mut target_grant = model["accessProfiles"][0]["permissions"][0].clone();
        target_grant["entity"] = json!("organization");
        model["accessProfiles"][0]["permissions"]
            .as_array_mut()
            .unwrap()
            .push(target_grant);
        model["entities"][0]["fields"].as_array_mut().unwrap().push(json!({"id":"organization","type":"reference","target":"organization","required":true,"classification":"internal"}));
        model["entities"][0]["constraints"]
            .as_array_mut()
            .unwrap()
            .push(json!({"kind":"unique","fields":["organization"]}));
        for key in ["readableFields", "writableFields"] {
            model["accessProfiles"][0]["permissions"][0][key]
                .as_array_mut()
                .unwrap()
                .push(json!("organization"));
        }
        let before = serde_norway::to_string(&model).unwrap().into_bytes();
        fs::write(&path, &before).unwrap();
        private::replace(&state.root().join("project/registry.yaml"), &before).unwrap();
        state.source_digest = capture(&state.project, &fs::read(&state.clients_file).unwrap())
            .unwrap()
            .digest;
        state.save().unwrap();
        let mut inspect = args(&state);
        inspect.entity = None;
        inspect.selector_field = None;
        inspect.readable_fields.clear();
        inspect.all_records = false;
        let inspection = run(inspect).unwrap();
        let record = inspection["entities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entity| entity["id"] == "record")
            .unwrap();
        for key in ["selectorFields", "readableFields"] {
            assert!(record[key]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["id"] == "organization" && field["type"] == "reference"));
        }
        assert!(!record["rowFields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field["id"] == "organization"));
        let selected = || {
            let mut selected = args(&state);
            selected.selector_field = Some("organization".into());
            selected.selector_profile = "by-organization".into();
            selected.readable_fields = vec!["organization".into(), "label".into()];
            selected
        };
        let preview = run(selected()).unwrap();
        assert_eq!(
            preview["changeSet"]["migrationPlan"]["statements"],
            json!([])
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        let root = state.root();
        private::directory(&root.join("build")).unwrap();
        private::directory(&root.join("build/package")).unwrap();
        let clients: Clients =
            serde_json::from_slice(&private::read(&root.join("clients.json"), MAX_BYTES).unwrap())
                .unwrap();
        config::runtime(
            &root,
            &state,
            &clients,
            state.package_revision.as_deref().unwrap(),
            false,
        )
        .unwrap();
        let mut apply = selected();
        apply.apply = true;
        assert_eq!(run(apply).unwrap()["status"], "prepared");
        let compiled = crate::compile(
            &state.project,
            crate::ProfileArg::Production,
            "prepare-source",
        )
        .unwrap_or_else(|failure| panic!("{}", serde_json::to_string(&failure).unwrap()));
        let export = registry_breg::evidence_source::export_evidence_source(
            &compiled,
            &registry_breg::evidence_source::EvidenceSourceOptions {
                access_profile: "source-reader".into(),
                entity: "record".into(),
                selectors: vec!["by-organization".into()],
                fields: vec!["organization".into(), "label".into()],
                source_id: "registry".into(),
                connection: "registry".into(),
            },
        )
        .unwrap();
        assert_eq!(
            export.identity_fields["by-organization"],
            Vec::<String>::new()
        );
        let facts = export
            .artifacts
            .iter()
            .find(|artifact| artifact.path == "schemas/registry-facts.yaml")
            .unwrap();
        let facts: Value = serde_json::from_slice(&facts.bytes).unwrap();
        assert_eq!(
            facts["properties"]["organization"],
            json!({"type":"string","minLength":36,"maxLength":36})
        );
    }

    #[test]
    fn changed_yaml_keeps_full_line_notes_with_their_original_sections() {
        let original = b"# Registry header\nregistry:\n  # Stable identity\n  id: example\n# Review scope explicitly\naccessProfiles: []\n";
        let mut value: Value = serde_norway::from_slice(original).unwrap();
        value["registry"]["id"] = json!("changed");
        let rendered = yaml_with_comments(&value, original).unwrap();
        assert_eq!(serde_norway::from_slice::<Value>(&rendered).unwrap(), value);
        let text = String::from_utf8(rendered).unwrap();
        assert!(text.starts_with("# Registry header\n"));
        assert!(text.contains("# Review scope explicitly\naccessProfiles:"));
        assert!(text.contains("# Stable identity\nregistry:"));
    }

    #[test]
    fn nonunique_selector_and_implicit_row_authority_are_refused() {
        let (_temporary, state) = source_fixture();
        let mut selected = args(&state);
        selected.selector_field = Some("label".into());
        assert!(run(selected).unwrap_err().to_string().contains("unique"));
        let mut selected = args(&state);
        selected.all_records = false;
        assert!(run(selected)
            .unwrap_err()
            .to_string()
            .contains("--all-records"));
    }
}
