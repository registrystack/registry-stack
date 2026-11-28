// SPDX-License-Identifier: Apache-2.0
//! Prepare an exact lookup-only development source against a ready BReg run.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use clap::Args;
use registry_platform_yaml::Reader;
use registry_rstack_dev::BregRun;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::local_files as private;

const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Args, Serialize)]
pub(super) struct PrepareSourceArgs {
    /// Existing project served by the development run.
    #[arg(value_name = "PROJECT", default_value = ".")]
    project: PathBuf,
    /// Ready development run serving this exact project.
    #[arg(long)]
    run_id: String,
    /// Declare development posture for the ready run.
    #[arg(long, value_name = "POSTURE")]
    #[serde(skip)]
    pub(super) posture: Option<String>,
    /// Record type authored directly in registry.yaml; omit to inspect available fields.
    #[arg(long = "record-type", value_name = "ID")]
    entity: Option<String>,
    /// Existing required scalar identifier with an exact single-field unique constraint.
    #[arg(long)]
    selector_field: Option<String>,
    /// Comma-separated selection of 1 to 16 readable fact fields; the identifier is also readable for identity verification.
    #[arg(long, value_delimiter = ',')]
    readable_fields: Vec<String>,
    /// Explicitly authorize lookup across all records of the selected Record type.
    #[arg(long, conflicts_with = "row_field")]
    all_records: bool,
    /// Existing string, text or vocabulary-code field that bounds permitted records.
    #[arg(long, requires_all = ["row_claim", "row_value_file"])]
    row_field: Option<String>,
    /// Nonreserved direct claim name for the fixed local row boundary.
    #[arg(long, requires = "row_field")]
    row_claim: Option<String>,
    /// Owner-only input file containing a nonsecret scope label as a JSON string of 1 to 512 bytes; stored in dev.yaml.
    #[arg(long, requires = "row_field")]
    row_value_file: Option<PathBuf>,
    /// Fresh dedicated development client ID.
    #[arg(long, default_value = "evidence-source")]
    client: String,
    /// Fresh lookup-only access profile ID for the selected Record type and facts.
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

fn evidence_source_options(
    args: &PrepareSourceArgs,
    entity: String,
) -> registry_breg::evidence_source::EvidenceSourceOptions {
    registry_breg::evidence_source::EvidenceSourceOptions {
        access_profile: args.access_profile.clone(),
        entity,
        selectors: vec![args.selector_profile.clone()],
        fields: args.readable_fields.clone(),
        source_id: args.source_id.clone(),
        connection: args.connection.clone(),
        authentication:
            registry_breg::evidence_source::EvidenceSourceAuthentication::StaticAuthorization,
        required_values: std::collections::BTreeMap::new(),
        optional_fields: Vec::new(),
        public_check: false,
    }
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
                .any(|c| c["type"] == "unique" && c["fields"] == json!([field["id"]]))
        })
}
/// The captured registry and module documents as JSON trees, read through the
/// shared reader's YAML subset. The capture already compiled them, so only
/// their trees are needed here.
fn documents(files: &BTreeMap<String, Vec<u8>>) -> Result<BTreeMap<String, Value>> {
    files
        .iter()
        .filter(|(path, _)| *path == "registry.yaml" || path.ends_with("/module.yaml"))
        .map(
            |(path, bytes)| match Reader::new(path.as_str()).scan(bytes) {
                Ok(node) => Ok((
                    path.clone(),
                    node.map_or(Value::Null, |node| node.to_json_value()),
                )),
                Err(report) => bail!(
                    "{path} is outside the YAML subset; correct it as the diagnostics say:\n{}",
                    report.render_human()
                ),
            },
        )
        .collect()
}
/// The Record types a document declares, keyed by id. A document whose
/// `recordTypes` is not a mapping is refused rather than read as empty, so a
/// source written in another shape never yields a silently empty inventory.
fn record_types<'a>(path: &str, doc: &'a Value) -> Result<&'a serde_json::Map<String, Value>> {
    doc["recordTypes"]
        .as_object()
        .with_context(|| format!("{path} must declare recordTypes as a mapping keyed by id"))
}
fn inventory(
    docs: &BTreeMap<String, Value>,
    compiled: &registry_breg::CompiledRegistry,
) -> Result<Value> {
    let mut entities = Vec::new();
    for (entity_id, entity) in docs
        .get("registry.yaml")
        .map(|doc| record_types("registry.yaml", doc))
        .transpose()?
        .into_iter()
        .flatten()
        .filter(|(id, _)| compiled.entities().contains_key(id.as_str()))
    {
        let fields = entity["fields"].as_array().cloned().unwrap_or_default();
        let supported = |field: &Value, selector: bool| {
            let Some(logical) = compiled
                .entities()
                .get(entity_id.as_str())
                .and_then(|entity| {
                    entity
                        .stored_fields
                        .iter()
                        .find(|stored| Some(stored.logical.id.as_str()) == field["id"].as_str())
                })
                .map(|field| &field.logical)
            else {
                return false;
            };
            let name = logical.id.as_bytes();
            let local_name = matches!(name.first(), Some(b'a'..=b'z'))
                && name.len() <= 64
                && name.iter().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
                });
            local_name
                && scalar(field)
                && if selector {
                    registry_breg::evidence_source::supports_selector_field(&logical.field_type)
                } else {
                    registry_breg::evidence_source::supports_scalar_fact(&logical.field_type)
                }
        };
        let describe = |field: &Value| json!({"id":field["id"],"type":field["type"]});
        entities.push(json!({"id":entity_id,"selectorFields":fields.iter().filter(|field|identifier(entity,field) && supported(field,true)).map(describe).collect::<Vec<_>>(),
            "readableFields":fields.iter().filter(|field|supported(field,false)).map(describe).collect::<Vec<_>>(),
            "rowFields":fields.iter().filter(|field|row_field(field) && supported(field,false)).map(describe).collect::<Vec<_>>()}));
    }
    Ok(Value::Array(entities))
}

pub(super) fn run(args: PrepareSourceArgs) -> Result<Value> {
    let run = BregRun::open(&args.run_id, &args.project)?;
    ensure!(
        run.synthetic_issuer(),
        "Run prepare-source with the runner's synthetic issuer."
    );
    let _lock = private::lock(&run.state.join("prepare-source.lock"))?;
    let journal = run.state.join("source-preparation.json");
    if journal.exists() {
        let pending: Pending = serde_json::from_slice(&private::read(&journal, 8 * MAX_BYTES)?)?;
        pending.finish(&run, &journal)?;
        return Ok(pending.report);
    }
    let captured = crate::capture_project_source(&run.project)
        .map_err(|_| anyhow::anyhow!("The authored registry could not be captured."))?;
    let compiled =
        crate::compile_captured_project(&captured, crate::ProfileArg::Production, "prepare-source")
            .map_err(|_| anyhow::anyhow!("The authored registry could not be compiled."))?;
    let package = registry_breg::package::load_package(
        &run.package,
        &registry_breg::package::PackageLoadContext {
            posture: registry_platform_config::Posture::Development,
        },
    )?;
    ensure!(compiled.revision() == package.registry().revision(),
        "The authored registry differs from the active package. Start a run from the current project.");
    let mut files = BTreeMap::from([("registry.yaml".to_owned(), captured.project_bytes)]);
    for asset in captured.project_assets {
        files.insert(
            asset.path.trim_start_matches("source/").to_owned(),
            asset.bytes,
        );
    }
    for module in captured.modules {
        files.insert(format!("modules/{}/module.yaml", module.id), module.bytes);
        for asset in module.assets {
            files.insert(format!("modules/{}/{}", module.id, asset.path), asset.bytes);
        }
    }
    let docs = documents(&files)?;
    let report = json!({"ok":true, "command":"prepare-source", "project":run.project,
        "status":"inspect", "entities":inventory(&docs, &compiled)?, "bregUrl":run.origin,
        "issuer":run.issuer, "audience":run.audience});
    if args.entity.is_none() {
        ensure!(
            !args.apply
                && args.selector_field.is_none()
                && args.readable_fields.is_empty()
                && !args.all_records
                && args.row_field.is_none(),
            "Select a record type, selector field, readable fields and explicit row authority."
        );
        return Ok(report);
    }
    let authored_plan = read_authoring(&run.dev_yaml)?;
    let plan = Reader::new("dev.yaml")
        .scan(&authored_plan)
        .map_err(|_| anyhow::anyhow!("The development plan is not valid YAML."))?
        .context("The development plan is empty.")?
        .to_json_value();
    ensure!(
        run.plan_matches(&plan)?,
        "The development plan changed after the run started."
    );
    let pending = prepare_successor(
        &args,
        &files,
        docs,
        SuccessorBaseline {
            registry: package.registry(),
            package_digest: package.package_digest(),
            principal_claim: &run.principal_claim,
            scratch: &run.state,
        },
        &authored_plan,
        plan,
        report,
    )?;
    if args.apply {
        private::replace(&journal, &serde_json::to_vec(&pending)?)?;
        pending.finish(&run, &journal)?;
    }
    Ok(pending.report)
}

struct SuccessorBaseline<'a> {
    registry: &'a registry_breg::CompiledRegistry,
    package_digest: &'a str,
    principal_claim: &'a str,
    scratch: &'a Path,
}

/// Check the exact proposed authoring and build its replacement bytes without
/// modifying the project. Applying those bytes remains the journal's job.
fn prepare_successor(
    args: &PrepareSourceArgs,
    files: &BTreeMap<String, Vec<u8>>,
    mut docs: BTreeMap<String, Value>,
    baseline: SuccessorBaseline<'_>,
    authored_plan: &[u8],
    mut plan: Value,
    mut report: Value,
) -> Result<Pending> {
    let compiled = baseline.registry;
    let entity_id = args.entity.as_ref().context("select --record-type")?;
    for value in [&args.client, &args.access_profile, &args.selector_profile] {
        if registry_platform_yaml::LocalId::new(value.as_str()).is_err() {
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
        bail!(
            "select --all-records or an explicit --row-field, --row-claim and --row-value-file binding"
        );
    }
    if docs.values().any(|doc| {
        doc["accessProfiles"]
            .as_object()
            .is_some_and(|profiles| profiles.contains_key(&args.access_profile))
    }) {
        bail!("access profile already exists; select a fresh dedicated profile ID");
    }
    let path = "registry.yaml".to_owned();
    let declared = docs
        .get(&path)
        .map(|doc| record_types(&path, doc))
        .transpose()?
        .is_some_and(|entities| entities.contains_key(entity_id));
    if !declared {
        bail!(
            "source preparation supports entities authored directly in registry.yaml; use the normal reviewed package lifecycle for module-owned entities"
        );
    }
    let entity = docs.get_mut(&path).unwrap()["recordTypes"]
        .get_mut(entity_id.as_str())
        .unwrap();
    let fields = entity["fields"]
        .as_array()
        .context("selected entity has no fields")?;
    if !fields
        .iter()
        .any(|f| f["id"] == *selector && identifier(entity, f))
    {
        bail!(
            "selector must be an existing required, bounded scalar field with an exact single-field unique constraint"
        );
    }
    for id in &args.readable_fields {
        if !fields.iter().any(|f| f["id"] == *id && scalar(f)) {
            bail!("readable fields must name existing bounded scalar facts");
        }
    }
    let mut row_boundaries = vec![];
    let mut claims = BTreeMap::from([("registry_purpose".into(), json!("evidence-source-read"))]);
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
        registry["accessProfiles"] = json!({});
    }
    // A row reach that binds no row is written as the keyword, never as an
    // empty list.
    let row_boundaries = if row_boundaries.is_empty() {
        json!("unrestricted")
    } else {
        Value::Array(row_boundaries)
    };
    registry["accessProfiles"].as_object_mut().context("access profiles missing")?.insert(args.access_profile.clone(), json!({
        "principalClaim":baseline.principal_claim,"requiredScopes":[scope],"requesterClients":[args.client],"requiredPurposes":["evidence-source-read"],
        "permissions":{"records":[{"recordType":entity_id,"operations":["lookup"],"readableFields":grant_fields,
            "lookups":[{"selector":args.selector_profile,"valueOrigin":"request"}],"rowBoundaries":row_boundaries}]}}));

    let people = plan["people"]
        .as_object_mut()
        .context("The development plan has no people.")?;
    ensure!(
        !people.contains_key(&args.client)
            && people
                .values()
                .all(|person| person["client"] != args.client),
        "The development client already exists. Choose a fresh client."
    );
    people.insert(
        args.client.clone(),
        json!({
            "subject":args.client, "client":args.client,
            "grants":{"breg":{"profile":args.access_profile, "scopes":[scope], "claims":claims}}
        }),
    );
    let registry_after = yaml_with_comments(registry, &files["registry.yaml"])?;
    let plan_after = yaml_with_comments(&plan, authored_plan)?;
    let candidate = tempfile::tempdir_in(baseline.scratch)?;
    for (relative, bytes) in files {
        let path = candidate.path().join(relative);
        fs::create_dir_all(
            path.parent()
                .context("candidate authoring path has no parent")?,
        )?;
        fs::write(
            path,
            if relative == "registry.yaml" {
                &registry_after
            } else {
                bytes
            },
        )?;
    }
    let successor = crate::compile(
        candidate.path(),
        crate::ProfileArg::Production,
        "prepare-source",
    )
    .map_err(|_| anyhow::anyhow!("The selected source authority does not compile."))?;
    registry_breg::authority::authority_inventory(&successor)?;
    registry_breg::evidence_source::export_evidence_source(
        &successor,
        &evidence_source_options(args, entity_id.clone()),
    )
    .map_err(|diagnostic| anyhow::anyhow!("{}", diagnostic.message))?;
    let changes = registry_breg::package::compiled_registry_change_set(
        baseline.registry,
        &successor,
        baseline.package_digest,
    );
    let migration = registry_breg::package::change_set_to_applicable_migration_plan(&changes)?;
    check_policy_only(&migration)?;
    report["client"] = json!(args.client);
    report["accessProfile"] = json!(args.access_profile);
    report["selectorProfile"] = json!(args.selector_profile);
    report["rowScope"] = row_scope;
    report["scopes"] = json!([scope]);
    report["status"] = json!(if args.apply { "prepared" } else { "preview" });
    report["requiresRestart"] = json!(args.apply);
    Ok(Pending {
        registry: Edit::new(&files["registry.yaml"], registry_after),
        plan: Edit::new(authored_plan, plan_after),
        report,
    })
}

#[derive(Deserialize, Serialize)]
struct Edit {
    before_sha256: String,
    after: Vec<u8>,
}

impl Edit {
    fn new(before: &[u8], after: Vec<u8>) -> Self {
        Self {
            before_sha256: registry_platform_config::sha256_uri(before),
            after,
        }
    }

    fn pending(&self, path: &Path) -> Result<bool> {
        let current = read_authoring(path)?;
        if current == self.after {
            return Ok(false);
        }
        ensure!(
            registry_platform_config::sha256_uri(&current) == self.before_sha256,
            "Source preparation cannot replace changed authoring file {}.",
            path.display()
        );
        Ok(true)
    }
}

#[derive(Deserialize, Serialize)]
struct Pending {
    registry: Edit,
    plan: Edit,
    report: Value,
}

impl Pending {
    fn finish(&self, run: &BregRun, journal: &Path) -> Result<()> {
        let registry = run.project.join("registry.yaml");
        let registry_pending = self.registry.pending(&registry)?;
        let plan_pending = self.plan.pending(&run.dev_yaml)?;
        if plan_pending {
            replace_authoring(&run.dev_yaml, &self.plan.after)?;
        }
        if registry_pending {
            replace_authoring(&registry, &self.registry.after)?;
        }
        fs::remove_file(journal)?;
        fs::File::open(&run.state)?.sync_all()?;
        Ok(())
    }
}

fn read_authoring(path: &Path) -> Result<Vec<u8>> {
    crate::read_bounded_source_file(path, "prepare-source", "authoring", MAX_BYTES).map_err(|_| {
        anyhow::anyhow!(
            "Source preparation requires a bounded ordinary authoring file at {}.",
            path.display()
        )
    })
}

fn replace_authoring(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("authoring path has no parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::metadata(path)?.permissions())?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn check_policy_only(plan: &registry_breg::package::MigrationPlan) -> Result<()> {
    if !plan.statements.is_empty() {
        bail!("source preparation requires a policy-only successor with no storage DDL");
    }
    Ok(())
}
pub(super) fn yaml_with_comments(value: &Value, original: &[u8]) -> Result<Vec<u8>> {
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

#[cfg(test)]
#[path = "prepare_source/tests.rs"]
mod tests;
