//! Guided local composition through public provider commands and ordinary
//! Evidence source imports. No provider state or runtime implementation is read.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::{IsTerminal as _, Read as _, Write as _},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use clap::Args;
use inquire::{validator::MinLengthValidator, MultiSelect, Password, Select};
use registry_evidence_authoring::validate::valid_local_identifier;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{authoring, evidence_binary, scaffold, source_import, target};

const MAX_PROVIDER_OUTPUT: u64 = 4 * 1024 * 1024;

/// The one consent this command accepts, stated wherever a review ends.
const APPLY_REMEDY: &str = "Re-run evidencectl source add with --apply to perform this connection.";

#[derive(Debug, Args)]
pub(crate) struct SourceAddArgs {
    /// Registry project containing a stopped retained Base Registry Engine development session.
    pub registry: PathBuf,
    /// Evidence project directory; defaults to the current directory.
    ///
    /// This command extends an editable project or creates a source-first
    /// editable project when the directory is absent.
    #[arg(long, default_value = ".")]
    pub project: PathBuf,
    /// Existing registry entity; prompted when omitted in a terminal.
    #[arg(long)]
    pub entity: Option<String>,
    /// Existing unique identifier field; prompted when omitted in a terminal.
    #[arg(long)]
    pub selector_field: Option<String>,
    /// Existing scalar facts to expose; comma-separated, prompted when omitted.
    #[arg(long, value_delimiter = ',')]
    pub fields: Vec<String>,
    /// Explicitly allow lookups across every record in the selected entity.
    #[arg(long, conflicts_with_all = ["row_field", "row_claim", "row_value_file"])]
    pub all_records: bool,
    /// Restrict the workload to records matching this existing field.
    #[arg(long)]
    pub row_field: Option<String>,
    /// Advanced: direct workload claim name; defaults to registry_source_row.
    #[arg(long)]
    pub row_claim: Option<String>,
    /// Private input file holding a nonsecret scope label as one JSON string; stored in dev-clients.yaml.
    #[arg(long)]
    pub row_value_file: Option<PathBuf>,
    /// Source identifier; defaults to a bounded registry- name derived from the entity.
    #[arg(long)]
    pub source_id: Option<String>,
    /// Shared connection name, also used for credential filenames.
    #[arg(long, default_value = "registry")]
    pub connection: String,
    /// Dedicated local source client label; defaults to a bounded name derived from the source identifier.
    #[arg(long)]
    pub client: Option<String>,
    /// Dedicated registry lookup access profile; defaults to a bounded name derived from the source identifier.
    #[arg(long)]
    pub access_profile: Option<String>,
    /// Registry selector profile; defaults to a bounded name derived from the source identifier.
    #[arg(long)]
    pub selector_profile: Option<String>,
    /// Local target to extend; defaults to PROJECT/targets/local.
    #[arg(long)]
    pub target: Option<PathBuf>,
    /// Perform the reviewed connection; without it this command reviews new choices only.
    #[arg(long)]
    pub apply: bool,
    /// Public Base Registry Engine tooling binary; otherwise BREGCTL_BIN or bregctl on PATH.
    #[arg(long)]
    pub bregctl_bin: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Inspection {
    entities: Vec<Entity>,
    #[serde(default)]
    recovered_prior_apply: bool,
    #[serde(flatten)]
    endpoints: Endpoints,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entity {
    id: String,
    selector_fields: Vec<Field>,
    readable_fields: Vec<Field>,
    row_fields: Vec<Field>,
}

#[derive(Debug, Deserialize)]
struct Field {
    id: String,
    #[serde(rename = "type")]
    kind: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Endpoints {
    breg_url: String,
    token_endpoint: String,
    audience: String,
}

struct Selection {
    entity: String,
    selector_field: String,
    fields: Vec<String>,
    source_id: String,
    client: String,
    access_profile: String,
    selector_profile: String,
    row: Option<RowScope>,
    // An interactive row value stays in a private file for the public command.
    _row_value: Option<tempfile::NamedTempFile>,
}

struct RowScope {
    field: String,
    claim: String,
    value_file: PathBuf,
}

pub(crate) fn run(args: SourceAddArgs) -> Result<ExitCode> {
    let binary = args
        .bregctl_bin
        .clone()
        .or_else(|| std::env::var_os("BREGCTL_BIN").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("bregctl"));
    check_public_bregctl(&binary)?;
    let terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let report = configure(args, terminal, &mut |arguments| {
        let bytes = public_output(&binary, arguments)?;
        let report: Value = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("BReg returned an invalid public JSON report"))?;
        if report.get("ok") != Some(&Value::Bool(true)) {
            return Err(provider_refusal(arguments, &bytes));
        }
        Ok(report)
    })?;
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    println!();
    Ok(ExitCode::SUCCESS)
}

/// The public provider commands this composition drives belong to one build,
/// so the tooling it runs must report the version this build published.
fn check_public_bregctl(binary: &Path) -> Result<()> {
    let expected = format!("bregctl {}", registry_platform_buildinfo::DISPLAY_VERSION);
    let requirement = format!(
        "source add drives public Base Registry Engine tooling and requires {expected} on PATH; set --bregctl-bin or BREGCTL_BIN to that binary"
    );
    let version = public_output(binary, &["--version".into()]).context(requirement.clone())?;
    if std::str::from_utf8(&version).ok().map(str::trim) != Some(expected.as_str()) {
        bail!(requirement);
    }
    Ok(())
}

fn configure(
    args: SourceAddArgs,
    terminal: bool,
    invoke: &mut impl FnMut(&[OsString]) -> Result<Value>,
) -> Result<Value> {
    let registry = plain_directory(&args.registry, "registry project")?;
    let project = project_destination(&args.project)?;
    let target_path = match &args.target {
        Some(path) => absolute_destination(path)?,
        None => project.join("targets/local"),
    };
    if !valid_local_identifier(&args.connection) {
        bail!("connection requires a local identifier of at most 64 characters");
    }
    let base = provider_args(&registry);
    let inspected = invoke(&base)?;
    let inspection: Inspection = serde_json::from_value(inspected)
        .map_err(|_| anyhow::anyhow!("BReg returned an incomplete source inspection"))?;
    if inspection.recovered_prior_apply {
        eprintln!(
            "Completed previously accepted BReg setup before reviewing these source choices."
        );
    }
    validate_endpoints(&inspection.endpoints)?;
    let selection = select(&args, &inspection, terminal)?;
    let mut prepare = base;
    add_pair(&mut prepare, "--entity", &selection.entity);
    add_pair(&mut prepare, "--selector-field", &selection.selector_field);
    add_pair(
        &mut prepare,
        "--readable-fields",
        selection.fields.join(","),
    );
    add_pair(&mut prepare, "--client", &selection.client);
    add_pair(&mut prepare, "--access-profile", &selection.access_profile);
    add_pair(
        &mut prepare,
        "--selector-profile",
        &selection.selector_profile,
    );
    add_pair(&mut prepare, "--source-id", &selection.source_id);
    add_pair(&mut prepare, "--connection", &args.connection);
    if let Some(row) = &selection.row {
        add_pair(&mut prepare, "--row-field", &row.field);
        add_pair(&mut prepare, "--row-claim", &row.claim);
        add_pair(&mut prepare, "--row-value-file", &row.value_file);
    } else {
        prepare.push("--all-records".into());
    }
    let preview = invoke(&prepare)?;
    validate_preparation(&preview, &selection, &inspection.endpoints)?;
    let binding = connection(&inspection.endpoints, &args.connection);
    target::check_local_connection(&target_path, &args.connection, &binding)?;
    if project.exists() {
        check_credential_outputs(
            &project,
            &args.connection,
            &registry,
            &selection.client,
            &selection.source_id,
            !args.apply,
            invoke,
        )?;
    }
    let row_scope = selection.row.as_ref().map_or_else(
        || json!({"kind": "all-records"}),
        |row| json!({"kind": "claim", "field": row.field, "claim": row.claim}),
    );
    let mut report = json!({
        "ok": true, "command": "source add", "status": "preview",
        "registry": registry, "project": project, "target": target_path,
        "entity": selection.entity, "selectorField": selection.selector_field,
        "fields": selection.fields, "sourceId": selection.source_id,
        "connection": args.connection, "client": selection.client,
        "accessProfile": selection.access_profile, "selectorProfile": selection.selector_profile,
        "rowScope": row_scope, "bregUrl": inspection.endpoints.breg_url,
        "tokenEndpoint": inspection.endpoints.token_endpoint, "audience": inspection.endpoints.audience,
        "requiresRestart": preview["requiresRestart"],
        "recoveredPriorApply": inspection.recovered_prior_apply || preview["recoveredPriorApply"] == true,
    });
    if !args.apply {
        eprintln!(
            "Reviewed a {}.{} lookup for facts [{}], scope {}, and dedicated client {}. No new choices were applied.",
            selection.entity,
            selection.selector_field,
            selection.fields.join(", "),
            selection.row.as_ref().map_or_else(
                || "all records in this entity".to_owned(),
                |row| format!(
                    "records matching {} and the supplied private value",
                    row.field
                ),
            ),
            selection.client,
        );
        eprintln!("{APPLY_REMEDY}");
        report["next"] = json!([APPLY_REMEDY]);
        return Ok(report);
    }

    if !project.exists() {
        scaffold::create_source_project(&project)?;
    }
    let lock = source_import::ProjectLock::acquire(&project)?;
    target::check_local_connection(&target_path, &args.connection, &binding)?;
    check_credential_outputs(
        &project,
        &args.connection,
        &registry,
        &selection.client,
        &selection.source_id,
        false,
        invoke,
    )?;
    // The provider alone writes its candidate, registrations and retained keys.
    // Its identical retry contract preserves the same pending activation.
    prepare.push("--apply".into());
    let prepared = invoke(&prepare)?;
    validate_preparation(&prepared, &selection, &inspection.endpoints)?;

    let exported = tempfile::tempdir().context("staging the public source export")?;
    let export = fs::canonicalize(exported.path())
        .context("resolving the public export staging directory")?
        .join("source");
    let mut generate = vec![
        "--format".into(),
        "json".into(),
        "generate".into(),
        "evidence-source".into(),
        registry.as_os_str().into(),
    ];
    add_pair(&mut generate, "--entity", &selection.entity);
    add_pair(&mut generate, "--access-profile", &selection.access_profile);
    add_pair(&mut generate, "--selector", &selection.selector_profile);
    add_pair(&mut generate, "--fields", selection.fields.join(","));
    add_pair(&mut generate, "--source-id", &selection.source_id);
    add_pair(&mut generate, "--connection", &args.connection);
    add_pair(&mut generate, "--output", &export);
    let generated = invoke(&generate)?;
    report["selectorProfiles"] = generated["explanation"]["selectorProfiles"].clone();
    let mut candidate = source_import::prepare(&lock, &[export], &BTreeMap::new())?;
    if !candidate.report().conflicts.is_empty() {
        bail!("source setup found authored import conflicts; use source diff and explicit source import resolutions before retrying");
    }
    candidate.validate(authoring::validate_source_artifact_graph)?;

    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent).context("creating the local target parent")?;
    }
    target::ensure_local_connection(&project, &target_path, &args.connection, binding)?;
    let id_path = project.join(format!("secrets/{}-client-id", args.connection));
    let key_path = project.join(format!("secrets/{}-client-key", args.connection));
    invoke(&export_client_args(
        &registry,
        &selection.client,
        &id_path,
        &key_path,
    ))?;
    candidate.apply(&lock)?;
    report["status"] = json!("prepared");
    report["requiresRestart"] = prepared["requiresRestart"].clone();
    if prepared["recoveredPriorApply"] == true {
        report["recoveredPriorApply"] = json!(true);
    }
    report["clientIdFile"] = json!(id_path);
    report["assertionKeyFile"] = json!(key_path);
    report["next"] = json!([
        "Author or review the Evidence question, derivation, and fixtures that use this source.",
        "Run evidencectl fixtures run --local with the reported project and target, then start BReg to activate its prepared package and run evidencectl dev --detach with that project and target."
    ]);
    Ok(report)
}

fn select(args: &SourceAddArgs, inspection: &Inspection, terminal: bool) -> Result<Selection> {
    let entity_id = choose(
        args.entity.as_deref(),
        inspection
            .entities
            .iter()
            .map(|entity| (entity.id.clone(), entity.id.clone()))
            .collect(),
        "Which registry entity supplies the facts?",
        "--entity",
        terminal,
    )?;
    let entity = inspection
        .entities
        .iter()
        .find(|entity| entity.id == entity_id)
        .context("the selected entity is absent from the registry inspection")?;
    let selector_field = choose(
        args.selector_field.as_deref(),
        field_choices(&entity.selector_fields),
        "Which unique identifier locates one record?",
        "--selector-field",
        terminal,
    )?;
    let mut fields = args.fields.clone();
    if fields.is_empty() {
        require_terminal(terminal, "--fields")?;
        let options = field_choices(&entity.readable_fields);
        if options.is_empty() {
            bail!("this entity has no exportable scalar facts");
        }
        let labels = options.iter().map(|(_, label)| label.clone()).collect();
        fields = MultiSelect::new("Which facts may the source client read?", labels)
            .with_validator(MinLengthValidator::new(1))
            .raw_prompt()
            .map_err(prompt_error)?
            .into_iter()
            .map(|item| options[item.index].0.clone())
            .collect();
    }
    let readable: BTreeSet<_> = entity
        .readable_fields
        .iter()
        .map(|field| field.id.as_str())
        .collect();
    if fields
        .iter()
        .any(|field| !readable.contains(field.as_str()))
    {
        bail!("--fields must name scalar facts offered by the registry inspection");
    }
    fields.sort();
    fields.dedup();
    let mut all_records = args.all_records;
    if !all_records
        && args.row_field.is_none()
        && args.row_value_file.is_none()
        && args.row_claim.is_none()
    {
        require_terminal(
            terminal,
            "--all-records or --row-field with --row-value-file",
        )?;
        all_records = Select::new(
            "Which records may this source client look up?",
            vec![
                "Records matching a fixed field value",
                "All records in this entity",
            ],
        )
        .raw_prompt()
        .map_err(prompt_error)?
        .index
            == 1;
    }
    let mut row_value = None;
    let row = if all_records {
        None
    } else {
        let field = choose(
            args.row_field.as_deref(),
            field_choices(&entity.row_fields),
            "Which field bounds the allowed records?",
            "--row-field",
            terminal,
        )?;
        let claim = args
            .row_claim
            .clone()
            .unwrap_or_else(|| "registry_source_row".to_owned());
        let value_file = match &args.row_value_file {
            Some(path) => fs::canonicalize(path).context("row value file must exist")?,
            None => {
                require_terminal(terminal, "--row-value-file")?;
                let raw = Zeroizing::new(
                    Password::new("Allowed field value (hidden)")
                        .with_help_message("Use a nonsecret scope label. This value is stored in dev-clients.yaml.")
                        .without_confirmation()
                        .prompt()
                        .map_err(prompt_error)?,
                );
                if raw.is_empty() || raw.len() > 512 {
                    bail!("the allowed row value must contain between 1 and 512 UTF-8 bytes");
                }
                let mut file =
                    tempfile::NamedTempFile::new().context("preparing a private row value file")?;
                let bytes = Zeroizing::new(serde_json::to_vec(raw.as_str())?);
                file.write_all(&bytes)?;
                file.as_file().sync_all()?;
                let path = file.path().to_path_buf();
                row_value = Some(file);
                path
            }
        };
        Some(RowScope {
            field,
            claim,
            value_file,
        })
    };
    let source_id = args
        .source_id
        .clone()
        .unwrap_or_else(|| provider_identifier_default(&format!("registry-{entity_id}")));
    let provider_id = provider_identifier_default(&source_id);
    let selector_profile = args
        .selector_profile
        .clone()
        .unwrap_or_else(|| provider_id.clone());
    let client = args.client.clone().unwrap_or_else(|| provider_id.clone());
    let access_profile = args.access_profile.clone().unwrap_or(provider_id);
    for (flag, value) in [
        ("--source-id", &source_id),
        ("--selector-profile", &selector_profile),
        ("--client", &client),
        ("--access-profile", &access_profile),
    ] {
        if !valid_local_identifier(value) {
            bail!("set {flag} to a local identifier of at most 64 characters");
        }
    }
    Ok(Selection {
        entity: entity_id,
        selector_field,
        fields,
        source_id,
        client,
        access_profile,
        selector_profile,
        row,
        _row_value: row_value,
    })
}

// Provider client and profile names accept fewer separators than Evidence
// source names. Preserve explicit names; derive only missing defaults. The
// digest keeps shortening from giving different long names the same default.
fn provider_identifier_default(value: &str) -> String {
    let mut identifier: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect();
    if identifier.len() > 64 {
        let digest = hex::encode(Sha256::digest(value.as_bytes()));
        identifier.truncate(55);
        identifier.push('-');
        identifier.push_str(&digest[..8]);
    }
    identifier
}

fn choose(
    provided: Option<&str>,
    options: Vec<(String, String)>,
    prompt: &str,
    flag: &str,
    terminal: bool,
) -> Result<String> {
    if let Some(value) = provided {
        if options.iter().any(|(id, _)| id == value) {
            return Ok(value.to_owned());
        }
        bail!("{flag} must name one of the registry's inspected choices");
    }
    require_terminal(terminal, flag)?;
    if options.is_empty() {
        bail!("the registry has no eligible choice for {flag}");
    }
    let selected = Select::new(
        prompt,
        options.iter().map(|(_, label)| label.clone()).collect(),
    )
    .raw_prompt()
    .map_err(prompt_error)?;
    Ok(options[selected.index].0.clone())
}

fn field_choices(fields: &[Field]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|field| {
            let kind = field.kind.as_str().unwrap_or("scalar");
            (field.id.clone(), format!("{} ({kind})", field.id))
        })
        .collect()
}

fn require_terminal(terminal: bool, flag: &str) -> Result<()> {
    if !terminal {
        bail!(
            "source add needs {flag} without an interactive terminal; name every choice explicitly"
        );
    }
    Ok(())
}

fn prompt_error(_: inquire::error::InquireError) -> anyhow::Error {
    anyhow::anyhow!(
        "source setup prompt cancelled or unavailable; no new source choices were applied"
    )
}

fn provider_args(registry: &Path) -> Vec<OsString> {
    vec![
        "--format".into(),
        "json".into(),
        "dev".into(),
        "prepare-source".into(),
        registry.as_os_str().into(),
    ]
}

fn export_client_args(
    registry: &Path,
    client: &str,
    id_path: &Path,
    key_path: &Path,
) -> Vec<OsString> {
    let mut arguments = vec![
        "--format".into(),
        "json".into(),
        "dev".into(),
        "export-client".into(),
        registry.as_os_str().into(),
    ];
    add_pair(&mut arguments, "--client", client);
    add_pair(&mut arguments, "--client-id-file", id_path);
    add_pair(&mut arguments, "--assertion-key-file", key_path);
    arguments
}

fn add_pair(arguments: &mut Vec<OsString>, flag: &str, value: impl AsRef<std::ffi::OsStr>) {
    arguments.push(flag.into());
    arguments.push(value.as_ref().into());
}

fn validate_preparation(report: &Value, selected: &Selection, expected: &Endpoints) -> Result<()> {
    let endpoints: Endpoints = serde_json::from_value(report.clone())
        .map_err(|_| anyhow::anyhow!("BReg preparation omitted its connection endpoints"))?;
    if &endpoints != expected
        || !report["requiresRestart"].is_boolean()
        || report["entity"] != selected.entity
        || report["selectorField"] != selected.selector_field
        || report["selectorProfile"] != selected.selector_profile
        || report["accessProfile"] != selected.access_profile
        || report["client"] != selected.client
        || report["readableFields"] != json!(selected.fields)
    {
        bail!("BReg preparation differs from the reviewed source choices; inspect the registry before retrying");
    }
    let expected_scope = selected.row.as_ref().map_or_else(
        || json!({"kind": "all-records"}),
        |row| json!({"kind": "claim", "field": row.field, "claim": row.claim}),
    );
    if report["rowScope"] != expected_scope {
        bail!("BReg preparation differs from the reviewed record scope");
    }
    Ok(())
}

fn validate_endpoints(endpoints: &Endpoints) -> Result<()> {
    for (value, path) in [
        (&endpoints.breg_url, "/"),
        (&endpoints.token_endpoint, "/token"),
    ] {
        let url = url::Url::parse(value).context("BReg reported an invalid local endpoint")?;
        let loopback = match url.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
        if url.scheme() != "http"
            || !loopback
            || url.port().is_none()
            || url.path() != path
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("BReg source setup requires fixed numeric-loopback development endpoints");
        }
    }
    if endpoints.audience.is_empty()
        || endpoints.audience.len() > 1024
        || endpoints.audience.chars().any(char::is_whitespace)
    {
        bail!("BReg reported an invalid token audience");
    }
    Ok(())
}

fn connection(endpoints: &Endpoints, name: &str) -> Value {
    json!({
        "baseUrl": endpoints.breg_url,
        "authentication": {
            "kind": "oauth2-client-credentials", "tokenEndpoint": endpoints.token_endpoint,
            "clientIdRef": format!("secret:file/{name}-client-id"),
            "clientAssertionKeyRef": format!("secret:file/{name}-client-key"),
            "audience": endpoints.audience, "maximumCacheSeconds": 60,
        },
        "concurrencyLimit": 4, "admissionTimeoutMilliseconds": 5000, "tokenTimeoutMilliseconds": 5000,
    })
}

fn plain_directory(path: &Path, what: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspecting {what}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("{what} must be an ordinary directory");
    }
    fs::canonicalize(path).with_context(|| format!("resolving {what}"))
}

fn project_destination(path: &Path) -> Result<PathBuf> {
    if fs::symlink_metadata(path).is_ok() {
        let project = plain_directory(path, "Evidence project")?;
        if !project
            .join(registry_evidence_authoring::PROJECT_MARKER_FILE)
            .is_file()
        {
            bail!("existing Evidence project requires evidence-project.yaml; choose a new directory or an existing editable project");
        }
        return Ok(project);
    }
    absolute_destination(path)
}

fn absolute_destination(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = plain_directory(parent, "destination parent")?;
    let name = path
        .file_name()
        .context("destination requires a directory name")?;
    Ok(parent.join(name))
}

fn check_credential_outputs(
    project: &Path,
    name: &str,
    registry: &Path,
    client: &str,
    source_id: &str,
    allow_missing_directory: bool,
    invoke: &mut impl FnMut(&[OsString]) -> Result<Value>,
) -> Result<()> {
    let secrets = project.join("secrets");
    let metadata = match fs::symlink_metadata(&secrets) {
        // A clean checkout can be previewed before its ignored keys exist.
        Err(error) if allow_missing_directory && error.kind() == std::io::ErrorKind::NotFound => {
            return check_missing_connection_credentials(project, name, source_id);
        }
        result => {
            result.context("Evidence project needs its generated private secrets directory")?
        }
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        bail!("Evidence secrets must be an ordinary owner-only directory");
    }
    let mut existing = Vec::new();
    for suffix in ["client-id", "client-key"] {
        match fs::symlink_metadata(secrets.join(format!("{name}-{suffix}"))) {
            Ok(metadata) if metadata.is_file() && metadata.nlink() == 1
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && matches!(metadata.mode() & 0o7777, 0o400 | 0o600) => existing.push(suffix),
            Ok(_) => bail!("source credential outputs must be owner-only ordinary files; existing files were preserved"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(error).context("inspecting source credential outputs"),
        }
    }
    if existing.is_empty() {
        return check_missing_connection_credentials(project, name, source_id);
    }
    // The public provider export owns credential identity and validity. Stage
    // its retained pair privately so preflight never fills a missing output,
    // including while a review reports the choices it would apply.
    let temporary = tempfile::tempdir().context("staging the retained credential comparison")?;
    let temporary_path = fs::canonicalize(temporary.path())
        .context("resolving the private credential staging directory")?;
    invoke(&export_client_args(
        registry,
        client,
        &temporary_path.join("client-id"),
        &temporary_path.join("client-key"),
    ))
    .context("existing connection credentials cannot be reused for the selected client; choose a fresh --connection before applying this source setup")?;
    for suffix in existing {
        let current = credential_bytes(&secrets.join(format!("{name}-{suffix}")))?;
        let retained = credential_bytes(&temporary_path.join(suffix))?;
        if current.as_slice() != retained.as_slice() {
            bail!("existing connection credentials differ from the selected retained client; choose a fresh --connection before applying this source setup; existing files were preserved");
        }
    }
    Ok(())
}

fn check_missing_connection_credentials(project: &Path, name: &str, source_id: &str) -> Result<()> {
    if authoring::source_connection_users(project, name)?
        .iter()
        .any(|user| user != source_id)
    {
        bail!("connection is already used by another source and its credential pair is absent; restore that connection's retained credentials or choose a fresh --connection before applying this source setup");
    }
    Ok(())
}

fn credential_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let file = fs::File::open(path).context("reading a source credential for comparison")?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_PROVIDER_OUTPUT + 1)
        .read_to_end(&mut bytes)
        .context("reading a bounded source credential")?;
    if bytes.len() as u64 > MAX_PROVIDER_OUTPUT {
        bail!("source credential exceeds its byte limit; existing files were preserved");
    }
    Ok(bytes)
}

fn public_output(binary: &Path, arguments: &[OsString]) -> Result<Vec<u8>> {
    let mut capture = tempfile::tempfile().context("capturing the public BReg report")?;
    let mut child = Command::new(binary)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::from(capture.try_clone()?))
        .stderr(Stdio::null())
        .spawn()
        .context("starting bregctl; set --bregctl-bin or BREGCTL_BIN if it is not on PATH")?;
    let status = evidence_binary::wait_bounded(
        &mut child,
        "BReg source command",
        Duration::from_secs(60),
        &|| Ok(()),
        &|| evidence_binary::capture_over_limit(&capture, MAX_PROVIDER_OUTPUT),
    )?;
    let bytes =
        evidence_binary::drain_capture(&mut capture, MAX_PROVIDER_OUTPUT, "BReg source command")?;
    if !status.success() {
        return Err(provider_refusal(arguments, &bytes));
    }
    Ok(bytes)
}

fn provider_refusal(arguments: &[OsString], bytes: &[u8]) -> anyhow::Error {
    let operation = if arguments.iter().any(|arg| arg == "prepare-source") {
        "dev prepare-source"
    } else if arguments.iter().any(|arg| arg == "export-client") {
        "dev export-client"
    } else if arguments.iter().any(|arg| arg == "evidence-source") {
        "generate evidence-source"
    } else {
        "--version"
    };
    // BReg's public diagnostic envelope owns value-free, actionable errors.
    // Raw stderr and unstructured output never become an Evidence diagnostic.
    let messages = serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|report| {
            if report["ok"] != false {
                return None;
            }
            let diagnostics = report["diagnostics"].as_array()?;
            let rendered: Vec<_> = diagnostics
                .iter()
                .take(8)
                .filter_map(|diagnostic| {
                    let code = diagnostic["code"].as_str()?;
                    let message = diagnostic["message"].as_str()?;
                    if code.is_empty()
                        || code.len() > 128
                        || !code.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'.' | b'_' | b'-')
                        })
                        || message.is_empty()
                        || message.len() > 4096
                        || message
                            .chars()
                            .any(|character| character.is_control() && character != '\n')
                    {
                        return None;
                    }
                    Some(format!("{code}: {message}"))
                })
                .collect();
            (!rendered.is_empty()).then(|| rendered.join("\n"))
        });
    match messages {
        Some(messages) => anyhow::anyhow!("bregctl {operation} refused:\n{messages}"),
        None => anyhow::anyhow!("bregctl {operation} failed without a public diagnostic; preserve both projects and run that public command to inspect the refusal before retrying source add"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn args(registry: &Path, project: &Path) -> SourceAddArgs {
        let cli = crate::Cli::try_parse_from([
            OsString::from("evidencectl"),
            "source".into(),
            "add".into(),
            registry.into(),
            "--project".into(),
            project.into(),
            "--entity".into(),
            "record".into(),
            "--selector-field".into(),
            "code".into(),
            "--fields".into(),
            "name".into(),
            "--all-records".into(),
            "--source-id".into(),
            "registry-name".into(),
            "--apply".into(),
        ])
        .unwrap();
        let crate::Command::Source(crate::source_cli::SourceCommand::Add(args)) = cli.command
        else {
            panic!("source add parsed");
        };
        args
    }

    fn option(arguments: &[OsString], flag: &str) -> String {
        arguments.windows(2).find(|pair| pair[0] == flag).unwrap()[1]
            .to_str()
            .unwrap()
            .to_owned()
    }

    struct Provider {
        calls: Vec<Vec<OsString>>,
        fail_export_once: bool,
        clients: BTreeSet<String>,
    }

    impl Provider {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
                fail_export_once: false,
                clients: BTreeSet::new(),
            }
        }

        fn invoke(&mut self, arguments: &[OsString]) -> Result<Value> {
            self.calls.push(arguments.to_vec());
            if arguments.iter().any(|arg| arg == "prepare-source") {
                let mut report = json!({"ok":true,"status":"inspect","requiresRestart":true,
                    "bregUrl":"http://127.0.0.1:19090","tokenEndpoint":"http://127.0.0.1:19091/token","audience":"urn:test:retained-session",
                    "entities":[{"id":"record","selectorFields":[{"id":"code","type":"string"}],
                        "readableFields":[{"id":"code","type":"string"},{"id":"name","type":"string"},{"id":"group","type":"string"}],
                        "rowFields":[{"id":"group","type":"string"}]}]});
                if arguments.iter().any(|arg| arg == "--entity") {
                    for (key, flag) in [
                        ("entity", "--entity"),
                        ("selectorField", "--selector-field"),
                        ("selectorProfile", "--selector-profile"),
                        ("accessProfile", "--access-profile"),
                        ("client", "--client"),
                    ] {
                        report[key] = json!(option(arguments, flag));
                    }
                    report["status"] = json!(if arguments.iter().any(|arg| arg == "--apply") {
                        self.clients.insert(option(arguments, "--client"));
                        "prepared"
                    } else {
                        "preview"
                    });
                    report["readableFields"] = json!(option(arguments, "--readable-fields")
                        .split(',')
                        .collect::<Vec<_>>());
                    report["rowScope"] = if arguments.iter().any(|arg| arg == "--all-records") {
                        json!({"kind":"all-records"})
                    } else {
                        json!({"kind":"claim","field":option(arguments,"--row-field"),"claim":option(arguments,"--row-claim")})
                    };
                    assert!(!option(arguments, "--source-id").is_empty());
                    assert!(!option(arguments, "--connection").is_empty());
                }
                return Ok(report);
            }
            if arguments.iter().any(|arg| arg == "generate") {
                let output = PathBuf::from(option(arguments, "--output"));
                assert_eq!(
                    fs::canonicalize(output.parent().unwrap())?,
                    output.parent().unwrap()
                );
                write_export(
                    Path::new(&option(arguments, "--output")),
                    &option(arguments, "--source-id"),
                    &option(arguments, "--connection"),
                )?;
                return Ok(
                    json!({"ok":true,"explanation":{"selectorProfiles":{"registry-name":"record-code"}}}),
                );
            }
            assert!(arguments.iter().any(|arg| arg == "export-client"));
            let client = option(arguments, "--client");
            if !self.clients.contains(&client) {
                bail!("selected client is absent from the retained session");
            }
            if self.fail_export_once {
                self.fail_export_once = false;
                bail!("simulated interruption before credential publication");
            }
            let key = format!("private-test-key-canary-{client}");
            for (flag, bytes) in [
                ("--client-id-file", client.as_bytes()),
                ("--assertion-key-file", key.as_bytes()),
            ] {
                let path = PathBuf::from(option(arguments, flag));
                assert_eq!(
                    fs::canonicalize(path.parent().unwrap())?,
                    path.parent().unwrap()
                );
                if path.exists() {
                    if fs::read(&path)? != bytes {
                        bail!("credential output conflicts with the retained pair");
                    }
                } else {
                    fs::write(&path, bytes)?;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                }
            }
            Ok(json!({"ok":true}))
        }
    }

    fn write_export(root: &Path, id: &str, connection: &str) -> Result<()> {
        let source = format!("transport: http-json\nconnection: {connection}\nrequest:\n  selectorInputs:\n    - role: subject\n      alternatives: [{{profile: record-code, fields: [code]}}]\n  prepareScript: adapters/{id}-prepare.rhai\n  adapterParametersSchema: schemas/{id}-parameters.yaml\nresponseSchema: schemas/{id}-response.yaml\nfactSchema: schemas/{id}-facts.yaml\nextractScript: adapters/{id}-extract.rhai\n");
        let artifacts = BTreeMap::from([
            (format!("sources/{id}.yaml"), source),
            (
                "selectors/record-code.yaml".to_owned(),
                "fields: {code: {type: string, minimumBytes: 1, maximumBytes: 128}}\n".to_owned(),
            ),
            (
                format!("schemas/{id}-parameters.yaml"),
                "type: object\nproperties: {}\nadditionalProperties: false\n".to_owned(),
            ),
            (
                format!("schemas/{id}-response.yaml"),
                "type: object\nproperties: {}\nadditionalProperties: false\n".to_owned(),
            ),
            (
                format!("schemas/{id}-facts.yaml"),
                "type: object\nproperties: {}\nadditionalProperties: false\n".to_owned(),
            ),
            (
                format!("adapters/{id}-prepare.rhai"),
                "fn prepare(selectors, context) { #{query: [], body: ()} }\n".to_owned(),
            ),
            (
                format!("adapters/{id}-extract.rhai"),
                "fn extract(response, context) { #{outcome: \"no_match\"} }\n".to_owned(),
            ),
        ]);
        for (relative, text) in &artifacts {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap())?;
            fs::write(path, text)?;
        }
        fs::write(
            root.join("source-export.json"),
            serde_json::to_vec(&json!({
                "formatVersion":1,"sourceId":id,"provenance":{"producer":"source-add-test","revision":"one"},
                "artifacts":artifacts.iter().map(|(path,text)|json!({"path":path,"sha256":hex::encode(Sha256::digest(text.as_bytes()))})).collect::<Vec<_>>()
            }))?,
        )?;
        Ok(())
    }

    #[test]
    fn source_first_setup_and_identical_retry_use_public_commands_and_report_actual_paths() {
        let root = tempfile::tempdir().unwrap();
        let registry = root.path().join("registry");
        fs::create_dir(&registry).unwrap();
        let project = root.path().join("evidence");
        let mut provider = Provider::new();
        let first = configure(args(&registry, &project), false, &mut |a| {
            provider.invoke(a)
        })
        .unwrap();
        let project = fs::canonicalize(project).unwrap();
        assert_eq!(first["status"], "prepared");
        assert_eq!(first["client"], "registry-name");
        assert_eq!(first["accessProfile"], "registry-name");
        assert_eq!(first["selectorProfile"], "registry-name");
        assert_eq!(
            first["selectorProfiles"],
            json!({"registry-name":"record-code"})
        );
        assert_eq!(first["requiresRestart"], true);
        assert_eq!(first["target"], json!(project.join("targets/local")));
        assert_eq!(fs::read_dir(project.join("questions")).unwrap().count(), 0);
        assert!(project.join("sources/registry-name.yaml").is_file());
        let (connections, _) =
            crate::build::local_dev_target_inputs(&project.join("targets/local")).unwrap();
        assert_eq!(connections["registry"]["baseUrl"], "http://127.0.0.1:19090");
        assert_eq!(
            connections["registry"]["authentication"]["tokenEndpoint"],
            "http://127.0.0.1:19091/token"
        );
        assert_eq!(
            connections["registry"]["authentication"]["audience"],
            "urn:test:retained-session"
        );
        let signing = fs::read(project.join("secrets/signing-p256-private-jwk")).unwrap();
        let target = fs::read(project.join("targets/local/governance.yaml")).unwrap();
        let second = configure(args(&registry, &project), false, &mut |a| {
            provider.invoke(a)
        })
        .unwrap();
        assert_eq!(first, second);
        // A matching retained pair proves valid existing-client reuse even
        // when the connection is already referenced by another source.
        check_credential_outputs(
            &project,
            "registry",
            &registry,
            "registry-name",
            "registry-other",
            false,
            &mut |a| provider.invoke(a),
        )
        .unwrap();
        assert_eq!(
            fs::read(project.join("secrets/signing-p256-private-jwk")).unwrap(),
            signing
        );
        assert_eq!(
            fs::read(project.join("targets/local/governance.yaml")).unwrap(),
            target
        );
        assert!(!first.to_string().contains("private-test-key-canary"));
        assert!(provider
            .calls
            .iter()
            .flatten()
            .all(|arg| arg != "start" && !arg.to_string_lossy().contains(".breg")));
    }

    #[test]
    fn a_preview_and_a_missing_scope_do_not_create_projects_or_apply_provider_changes() {
        let root = tempfile::tempdir().unwrap();
        let mut provider = Provider::new();
        let project = root.path().join("evidence");
        let mut selected = args(root.path(), &project);
        selected.apply = false;
        let report = configure(selected, false, &mut |a| {
            let mut report = provider.invoke(a)?;
            report["recoveredPriorApply"] = json!(!a.iter().any(|arg| arg == "--entity"));
            report["requiresRestart"] = json!(false);
            Ok(report)
        })
        .unwrap();
        assert_eq!(report["status"], "preview");
        assert_eq!(report["requiresRestart"], false);
        assert_eq!(report["recoveredPriorApply"], true);
        assert!(!project.exists());
        assert_eq!(provider.calls.len(), 2);
        let mut selected = args(root.path(), &project);
        selected.all_records = false;
        let error = configure(selected, false, &mut |a| provider.invoke(a)).unwrap_err();
        assert!(error.to_string().contains("--all-records or --row-field"));
        assert!(!project.exists());
        assert!(provider.calls.iter().flatten().all(|arg| arg != "--apply"));
    }

    #[test]
    fn a_preview_accepts_a_clean_project_without_secrets_but_apply_still_requires_them() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("evidence");
        fs::create_dir_all(project.join("questions")).unwrap();
        fs::create_dir(project.join("sources")).unwrap();
        let marker = b"version: 1\n";
        fs::write(project.join("evidence-project.yaml"), marker).unwrap();
        let mut provider = Provider::new();
        let mut preview = args(root.path(), &project);
        preview.apply = false;
        let report = configure(preview, false, &mut |a| provider.invoke(a)).unwrap();
        assert_eq!(report["status"], "preview");
        assert_eq!(
            provider.calls.len(),
            2,
            "preview needs only inspection and provider preview"
        );

        let error = configure(args(root.path(), &project), false, &mut |a| {
            provider.invoke(a)
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("generated private secrets directory"));
        assert!(provider.clients.is_empty());
        assert!(provider
            .calls
            .iter()
            .flatten()
            .all(|argument| argument != "--apply"));
        let entries: BTreeSet<_> = fs::read_dir(&project)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            BTreeSet::from([
                OsString::from("evidence-project.yaml"),
                OsString::from("questions"),
                OsString::from("sources"),
            ])
        );
        assert_eq!(
            fs::read(project.join("evidence-project.yaml")).unwrap(),
            marker
        );
        for directory in ["questions", "sources"] {
            assert_eq!(fs::read_dir(project.join(directory)).unwrap().count(), 0);
        }
    }

    #[test]
    fn row_scope_uses_a_private_file_and_never_places_its_value_in_arguments_or_report() {
        let root = tempfile::tempdir().unwrap();
        let value_file = root.path().join("row-value.json");
        fs::write(&value_file, b"\"private-row-value-canary\"").unwrap();
        fs::set_permissions(&value_file, fs::Permissions::from_mode(0o600)).unwrap();
        let mut selected = args(root.path(), &root.path().join("evidence"));
        selected.all_records = false;
        selected.row_field = Some("group".into());
        selected.row_value_file = Some(value_file);
        selected.apply = false;
        let mut provider = Provider::new();
        let report = configure(selected, false, &mut |a| provider.invoke(a)).unwrap();
        assert_eq!(
            report["rowScope"],
            json!({"kind":"claim","field":"group","claim":"registry_source_row"})
        );
        assert!(!report.to_string().contains("private-row-value-canary"));
        assert!(provider
            .calls
            .iter()
            .flatten()
            .all(|arg| !arg.to_string_lossy().contains("private-row-value-canary")));
    }

    #[test]
    fn interrupted_export_retries_and_connection_conflict_refuses_before_provider_apply() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("evidence");
        let mut provider = Provider::new();
        provider.fail_export_once = true;
        assert!(
            configure(args(root.path(), &project), false, &mut |a| provider
                .invoke(a))
            .is_err()
        );
        assert!(!project.join("sources/registry-name.yaml").exists());
        let signing = fs::read(project.join("secrets/signing-p256-private-jwk")).unwrap();
        configure(args(root.path(), &project), false, &mut |a| {
            provider.invoke(a)
        })
        .unwrap();
        assert_eq!(
            fs::read(project.join("secrets/signing-p256-private-jwk")).unwrap(),
            signing
        );
        let governance = project.join("targets/local/governance.yaml");
        let mut document: Value =
            serde_norway::from_slice(&fs::read(&governance).unwrap()).unwrap();
        document["sourceConnections"]["registry"]["baseUrl"] = json!("http://127.0.0.1:29090");
        fs::write(&governance, serde_norway::to_string(&document).unwrap()).unwrap();
        let before = fs::read(&governance).unwrap();
        provider.calls.clear();
        let error = configure(args(root.path(), &project), false, &mut |a| {
            provider.invoke(a)
        })
        .unwrap_err();
        assert!(error.to_string().contains("different authored settings"));
        assert!(provider.calls.iter().flatten().all(|arg| arg != "--apply"));
        assert_eq!(fs::read(governance).unwrap(), before);
    }

    #[test]
    fn another_source_cannot_reuse_connection_credentials_before_provider_apply() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("evidence");
        let mut provider = Provider::new();
        configure(args(root.path(), &project), false, &mut |a| {
            provider.invoke(a)
        })
        .unwrap();
        let id_path = project.join("secrets/registry-client-id");
        let key_path = project.join("secrets/registry-client-key");
        let id_before = fs::read(&id_path).unwrap();
        let key_before = fs::read(&key_path).unwrap();
        let governance_path = project.join("targets/local/governance.yaml");
        let governance_before = fs::read(&governance_path).unwrap();
        provider.calls.clear();

        let mut selected = args(root.path(), &project);
        selected.source_id = Some("registry-other".into());
        let error = configure(selected, false, &mut |a| provider.invoke(a)).unwrap_err();
        assert!(
            provider
                .calls
                .iter()
                .flatten()
                .all(|argument| argument != "--apply"),
            "credential reuse must be refused before preparing another registry client"
        );
        assert!(error.to_string().contains("connection"));
        assert!(!format!("{error:#}").contains("private-test-key-canary"));
        assert_eq!(fs::read(id_path).unwrap(), id_before);
        assert_eq!(fs::read(key_path).unwrap(), key_before);
        assert_eq!(fs::read(governance_path).unwrap(), governance_before);
        assert!(!project.join("sources/registry-other.yaml").exists());
        assert!(!provider.clients.contains("registry-other"));
    }

    #[test]
    fn missing_credentials_do_not_make_another_sources_connection_available() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("evidence");
        let mut provider = Provider::new();
        configure(args(root.path(), &project), false, &mut |a| {
            provider.invoke(a)
        })
        .unwrap();
        let source_path = project.join("sources/registry-name.yaml");
        let source_before = fs::read(&source_path).unwrap();
        let governance_path = project.join("targets/local/governance.yaml");
        let governance_before = fs::read(&governance_path).unwrap();
        for suffix in ["client-id", "client-key"] {
            fs::remove_file(project.join(format!("secrets/registry-{suffix}"))).unwrap();
        }

        for apply in [true, false] {
            provider.calls.clear();
            let mut selected = args(root.path(), &project);
            selected.source_id = Some("registry-other".into());
            selected.apply = apply;
            let error = configure(selected, false, &mut |a| provider.invoke(a)).unwrap_err();
            assert!(error.to_string().contains("connection"));
            assert!(provider
                .calls
                .iter()
                .flatten()
                .all(|argument| argument != "--apply"));
            assert!(!provider.clients.contains("registry-other"));
            assert!(!project.join("sources/registry-other.yaml").exists());
            for suffix in ["client-id", "client-key"] {
                assert!(!project.join(format!("secrets/registry-{suffix}")).exists());
            }
        }
        assert_eq!(fs::read(&source_path).unwrap(), source_before);
        assert_eq!(fs::read(&governance_path).unwrap(), governance_before);

        let mut selected = args(root.path(), &project);
        selected.source_id = Some("registry-other".into());
        selected.connection = "registry-other".into();
        configure(selected, false, &mut |a| provider.invoke(a)).unwrap();
        let source: Value = serde_norway::from_slice(
            &fs::read(project.join("sources/registry-other.yaml")).unwrap(),
        )
        .unwrap();
        assert_eq!(source["connection"], "registry-other");
        assert_eq!(fs::read(&source_path).unwrap(), source_before);
        for suffix in ["client-id", "client-key"] {
            assert!(project
                .join(format!("secrets/registry-other-{suffix}"))
                .is_file());
            assert!(!project.join(format!("secrets/registry-{suffix}")).exists());
        }

        fs::remove_dir_all(project.join("secrets")).unwrap();
        provider.calls.clear();
        let mut preview = args(root.path(), &project);
        preview.source_id = Some("third-source".into());
        preview.apply = false;
        let error = configure(preview, false, &mut |a| provider.invoke(a)).unwrap_err();
        assert!(error.to_string().contains("connection"));
        assert!(provider
            .calls
            .iter()
            .flatten()
            .all(|argument| argument != "--apply"));
        assert!(!project.join("secrets").exists());
    }

    #[test]
    fn a_mismatched_key_is_refused_before_apply_even_when_the_client_id_matches() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("evidence");
        let mut provider = Provider::new();
        configure(args(root.path(), &project), false, &mut |a| {
            provider.invoke(a)
        })
        .unwrap();
        let key_path = project.join("secrets/registry-client-key");
        fs::write(&key_path, b"different-private-key-canary").unwrap();
        for apply in [true, false] {
            provider.calls.clear();
            let mut selected = args(root.path(), &project);
            selected.apply = apply;
            let error = configure(selected, false, &mut |a| provider.invoke(a)).unwrap_err();
            assert!(error.to_string().contains("choose a fresh --connection"));
            assert!(!format!("{error:#}").contains("different-private-key-canary"));
            assert!(provider
                .calls
                .iter()
                .flatten()
                .all(|argument| argument != "--apply"));
            assert_eq!(
                fs::read(&key_path).unwrap(),
                b"different-private-key-canary"
            );
        }
    }

    #[test]
    fn partial_credentials_stay_missing_in_a_preview_and_exact_retry_restores_them() {
        for missing_suffixes in [
            vec!["client-id"],
            vec!["client-key"],
            vec!["client-id", "client-key"],
        ] {
            let root = tempfile::tempdir().unwrap();
            let project = root.path().join("evidence");
            let mut provider = Provider::new();
            configure(args(root.path(), &project), false, &mut |a| {
                provider.invoke(a)
            })
            .unwrap();
            let missing: Vec<_> = missing_suffixes
                .into_iter()
                .map(|suffix| {
                    let path = project.join(format!("secrets/registry-{suffix}"));
                    let retained = fs::read(&path).unwrap();
                    fs::remove_file(&path).unwrap();
                    (path, retained)
                })
                .collect();
            provider.calls.clear();

            let mut preview = args(root.path(), &project);
            preview.apply = false;
            let report = configure(preview, false, &mut |a| provider.invoke(a)).unwrap();
            assert_eq!(report["status"], "preview");
            assert!(
                missing.iter().all(|(path, _)| !path.exists()),
                "preflight must not publish a missing credential"
            );
            assert!(provider
                .calls
                .iter()
                .flatten()
                .all(|argument| argument != "--apply"));

            configure(args(root.path(), &project), false, &mut |a| {
                provider.invoke(a)
            })
            .unwrap();
            for (path, retained) in missing {
                assert_eq!(fs::read(path).unwrap(), retained);
            }
        }
    }

    #[test]
    fn public_refusals_name_the_operation_and_relay_only_bounded_structured_diagnostics() {
        let arguments = vec!["dev".into(), "export-client".into()];
        let report = json!({"ok":false,"diagnostics":[{"code":"dev.failed","message":"credential output conflicts; choose a fresh connection name"}],"private":"private-canary"});
        let message =
            provider_refusal(&arguments, &serde_json::to_vec(&report).unwrap()).to_string();
        assert!(message.contains("bregctl dev export-client"));
        assert!(message.contains("choose a fresh connection name"));
        assert!(!message.contains("private-canary"));
        assert!(!provider_refusal(&arguments, b"private-stderr-canary")
            .to_string()
            .contains("private-stderr-canary"));
    }

    #[test]
    fn cli_refuses_conflicting_record_scope_and_inspected_endpoint_must_be_local() {
        let result = crate::Cli::try_parse_from([
            "evidencectl",
            "source",
            "add",
            "registry",
            "--all-records",
            "--row-field",
            "group",
        ]);
        assert!(result.is_err());
        let endpoints = Endpoints {
            breg_url: "https://provider.example".into(),
            token_endpoint: "http://127.0.0.1:9091/token".into(),
            audience: "urn:test".into(),
        };
        assert!(validate_endpoints(&endpoints).is_err());
    }

    #[test]
    fn source_identifier_defaults_avoid_teaching_profile_and_selector_names() {
        let root = tempfile::tempdir().unwrap();
        let mut provider = Provider::new();
        let inspection: Inspection =
            serde_json::from_value(provider.invoke(&provider_args(root.path())).unwrap()).unwrap();
        let mut arguments = args(root.path(), &root.path().join("evidence"));
        arguments.source_id = None;
        let selected = select(&arguments, &inspection, false).unwrap();
        assert_eq!(selected.source_id, "registry-record");
        assert_eq!(selected.client, selected.source_id);
        assert_eq!(selected.access_profile, selected.source_id);
        assert_eq!(selected.selector_profile, selected.source_id);
        assert_ne!(selected.access_profile, "evidence-source");
        assert_ne!(selected.selector_profile, "by-code");
        arguments.client = Some("custom-client".into());
        arguments.access_profile = Some("custom-profile".into());
        arguments.selector_profile = Some("custom-selector".into());
        let selected = select(&arguments, &inspection, false).unwrap();
        assert_eq!(selected.client, "custom-client");
        assert_eq!(selected.access_profile, "custom-profile");
        assert_eq!(selected.selector_profile, "custom-selector");
    }

    #[test]
    fn provider_defaults_accept_underscores_and_bound_long_entity_names() {
        let root = tempfile::tempdir().unwrap();
        let mut provider = Provider::new();
        let mut inspection: Inspection =
            serde_json::from_value(provider.invoke(&provider_args(root.path())).unwrap()).unwrap();
        let mut arguments = args(root.path(), &root.path().join("evidence"));
        arguments.source_id = None;

        let mut derived = Vec::new();
        for entity in [
            "birth_record".to_owned(),
            format!("{}a", "r".repeat(62)),
            format!("{}b", "r".repeat(62)),
        ] {
            inspection.entities[0].id = entity.clone();
            arguments.entity = Some(entity);
            let selected = select(&arguments, &inspection, false).unwrap();
            for identifier in [
                &selected.source_id,
                &selected.client,
                &selected.access_profile,
                &selected.selector_profile,
            ] {
                assert!(valid_local_identifier(identifier), "{identifier}");
                assert!(identifier.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'-'));
            }
            assert_eq!(
                selected.source_id,
                select(&arguments, &inspection, false).unwrap().source_id,
                "retries must derive the same names"
            );
            assert_eq!(selected.client, selected.source_id);
            assert_eq!(selected.access_profile, selected.source_id);
            assert_eq!(selected.selector_profile, selected.source_id);
            derived.push(selected.source_id);
        }
        assert_eq!(derived[0], "registry-birth-record");
        assert_eq!(derived[1].len(), 64);
        assert_eq!(derived[2].len(), 64);
        assert_ne!(derived[1], derived[2]);

        arguments.source_id = Some("chosen_source".to_owned());
        let selected = select(&arguments, &inspection, false).unwrap();
        assert_eq!(selected.source_id, "chosen_source");
        assert_eq!(selected.client, "chosen-source");
        assert_eq!(selected.access_profile, "chosen-source");
        assert_eq!(selected.selector_profile, "chosen-source");
    }

    #[test]
    fn a_preview_is_the_default_and_apply_is_the_only_consent() {
        let root = tempfile::tempdir().unwrap();
        let registry = fs::canonicalize(root.path()).unwrap();
        let project = root.path().join("evidence");
        let cli = crate::Cli::try_parse_from([
            OsString::from("evidencectl"),
            "source".into(),
            "add".into(),
            registry.as_os_str().into(),
            "--project".into(),
            project.as_os_str().into(),
            "--entity".into(),
            "record".into(),
            "--selector-field".into(),
            "code".into(),
            "--fields".into(),
            "name".into(),
            "--all-records".into(),
        ])
        .unwrap();
        let crate::Command::Source(crate::source_cli::SourceCommand::Add(preview)) = cli.command
        else {
            panic!("source add parsed");
        };
        assert!(!preview.apply, "source add reviews choices without --apply");
        let mut provider = Provider::new();
        let report = configure(preview, false, &mut |a| provider.invoke(a)).unwrap();
        assert_eq!(report["status"], "preview");
        assert_eq!(report["next"], json!([APPLY_REMEDY]));
        assert!(APPLY_REMEDY.contains("--apply"));
        assert!(!project.exists());
        assert!(provider.clients.is_empty());
        assert!(provider
            .calls
            .iter()
            .flatten()
            .all(|argument| argument != "--apply"));
        // The withdrawn review flag must not become an accepted unknown argument.
        assert!(crate::Cli::try_parse_from([
            "evidencectl",
            "source",
            "add",
            "registry",
            "--all-records",
            "--dry-run",
        ])
        .is_err());

        let applied = configure(args(&registry, &project), false, &mut |a| {
            provider.invoke(a)
        })
        .unwrap();
        assert_eq!(applied["status"], "prepared");
        assert!(provider
            .calls
            .iter()
            .flatten()
            .any(|argument| argument == "--apply"));
    }

    #[test]
    fn every_bregctl_invocation_names_the_public_flags_source_add_declares() {
        let root = tempfile::tempdir().unwrap();
        let registry = fs::canonicalize(root.path()).unwrap();
        let project = root.path().join("evidence");
        let public = |command: &str, operation: &str| -> Vec<OsString> {
            vec![
                "--format".into(),
                "json".into(),
                command.into(),
                operation.into(),
                registry.as_os_str().into(),
            ]
        };
        let mut prepare = public("dev", "prepare-source");
        for (flag, value) in [
            ("--entity", "record"),
            ("--selector-field", "code"),
            ("--readable-fields", "name"),
            ("--client", "registry-name"),
            ("--access-profile", "registry-name"),
            ("--selector-profile", "registry-name"),
            ("--source-id", "registry-name"),
            ("--connection", "registry"),
        ] {
            add_pair(&mut prepare, flag, value);
        }
        prepare.push("--all-records".into());

        let mut provider = Provider::new();
        let mut preview = args(&registry, &project);
        preview.apply = false;
        configure(preview, false, &mut |a| provider.invoke(a)).unwrap();
        assert_eq!(
            provider.calls,
            vec![public("dev", "prepare-source"), prepare.clone()],
            "a preview inspects the registry and reviews one preparation"
        );

        provider.calls.clear();
        configure(args(&registry, &project), false, &mut |a| {
            provider.invoke(a)
        })
        .unwrap();
        let project = fs::canonicalize(&project).unwrap();
        let mut applied = prepare.clone();
        applied.push("--apply".into());
        let export = PathBuf::from(provider.calls[3].last().unwrap());
        assert!(export.is_absolute() && export.file_name().unwrap() == "source");
        let mut generate = public("generate", "evidence-source");
        for (flag, value) in [
            ("--entity", "record"),
            ("--access-profile", "registry-name"),
            ("--selector", "registry-name"),
            ("--fields", "name"),
            ("--source-id", "registry-name"),
            ("--connection", "registry"),
        ] {
            add_pair(&mut generate, flag, value);
        }
        add_pair(&mut generate, "--output", &export);
        let mut export_client = public("dev", "export-client");
        add_pair(&mut export_client, "--client", "registry-name");
        add_pair(
            &mut export_client,
            "--client-id-file",
            project.join("secrets/registry-client-id"),
        );
        add_pair(
            &mut export_client,
            "--assertion-key-file",
            project.join("secrets/registry-client-key"),
        );
        assert_eq!(
            provider.calls,
            vec![
                public("dev", "prepare-source"),
                prepare,
                applied,
                generate,
                export_client,
            ],
            "an applying run drives exactly these public commands"
        );
    }

    #[test]
    fn a_missing_or_different_bregctl_is_refused_by_name_and_expected_version() {
        let root = tempfile::tempdir().unwrap();
        let expected = format!("bregctl {}", registry_platform_buildinfo::DISPLAY_VERSION);
        let script = |name: &str, reported: &str| {
            let path = root.path().join(name);
            fs::write(&path, format!("#!/bin/sh\necho '{reported}'\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        };
        for binary in [
            root.path().join("absent-bregctl"),
            script("other-bregctl", "bregctl 0.0.0-other"),
            script(
                "other-tool",
                &format!("evidence {}", registry_platform_buildinfo::DISPLAY_VERSION),
            ),
        ] {
            let error = format!("{:#}", check_public_bregctl(&binary).unwrap_err());
            assert!(error.contains(&expected), "{error}");
            assert!(error.contains("--bregctl-bin"), "{error}");
            assert!(error.contains("BREGCTL_BIN"), "{error}");
        }
        check_public_bregctl(&script("bregctl", &expected)).unwrap();
    }

    #[test]
    fn the_long_help_states_the_matching_bregctl_requirement() {
        let command = crate::command();
        let add = command
            .get_subcommands()
            .find(|command| command.get_name() == "source")
            .expect("evidencectl publishes source")
            .get_subcommands()
            .find(|command| command.get_name() == "add")
            .expect("source publishes add");
        let long = add
            .get_long_about()
            .expect("source add states its tooling requirement")
            .to_string();
        assert!(long.contains("bregctl") && long.contains("PATH"), "{long}");
        assert!(long.contains("--apply"), "{long}");
        let apply = add
            .get_arguments()
            .find(|argument| argument.get_long() == Some("apply"))
            .expect("source add publishes --apply");
        assert!(!apply.is_hide_set());
        assert!(
            add.get_arguments()
                .all(|argument| argument.get_long() != Some("dry-run")),
            "the withdrawn review flag must be absent"
        );
    }
}
