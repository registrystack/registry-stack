//! Optional local source exports, explicit three-way updates, and recoverable
//! authoring mutations. Export provenance never supplies runtime authority.

mod files;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::Args;
use registry_evidence_authoring::validate::valid_local_identifier;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) use files::ProjectLock;
use files::{
    artifact_path, authored_bound, digest, read, snapshot, write, Contents, JOURNAL_PATH,
    MAX_FILE_BYTES, MAX_JOURNAL_BYTES, MAX_STATE_BYTES, STATE_PATH,
};

const MANIFEST_FILE: &str = "source-export.json";
const MAX_ARTIFACTS: usize = 256;
const MAX_EXPORT_BYTES: usize = 16 * 1024 * 1024;

/// The same export set and explicit resolutions are usable for a read-only
/// comparison and for accepting the resulting candidate.
#[derive(Debug, Args)]
pub(crate) struct ImportArgs {
    /// Complete local export directories; pass shared owners together.
    #[arg(required = true, num_args = 1..)]
    pub exports: Vec<PathBuf>,
    /// Editable Evidence project directory.
    #[arg(long, default_value = ".")]
    pub project: PathBuf,
    /// Closed versioned file choosing keep, adopt, or an explicitly resolved file.
    #[arg(long)]
    pub resolutions: Option<PathBuf>,
    /// Complete target used by the compiler to compare actual question revisions.
    #[arg(long)]
    pub target: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct DetachArgs {
    /// Installed source to fork into ordinary maintained authored files.
    pub source_id: String,
    #[arg(long, default_value = ".")]
    pub project: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportManifest {
    format_version: u32,
    source_id: String,
    provenance: BTreeMap<String, String>,
    artifacts: Vec<ExportArtifact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExportArtifact {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstalledExport {
    manifest: ExportManifest,
    /// The actual last upstream bytes, independent of accepted customization.
    upstream: BTreeMap<String, String>,
    /// Deleted upstream artifacts intentionally kept locally retain their last
    /// upstream bytes and origin in this source's record.
    #[serde(default)]
    retained: BTreeMap<String, RetainedArtifact>,
    #[serde(default)]
    detached: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedArtifact {
    upstream: String,
    provenance: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    format_version: u32,
    imports: BTreeMap<String, InstalledExport>,
    /// Exact accepted local content, including keep/resolved choices. Current
    /// authored bytes may subsequently differ and are read anew for every plan.
    accepted: BTreeMap<String, Option<String>>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            format_version: 1,
            imports: BTreeMap::new(),
            accepted: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "choice", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Resolution {
    Keep,
    Adopt,
    File { path: PathBuf },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResolutionFile {
    format_version: u32,
    artifacts: BTreeMap<String, Resolution>,
}

pub(crate) fn read_resolutions(path: Option<&Path>) -> Result<BTreeMap<String, Resolution>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let parent = files::plain_directory(
        path.parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("resolution file needs a UTF-8 name"))?;
    let content =
        read(&parent, name, MAX_FILE_BYTES)?.ok_or_else(|| anyhow!("resolution file is absent"))?;
    let mut resolutions: ResolutionFile =
        serde_json::from_str(&content.text).context("parsing the closed source resolution file")?;
    if resolutions.format_version != 1 || resolutions.artifacts.len() > MAX_ARTIFACTS {
        bail!("source resolution file requires formatVersion 1 and at most 256 artifacts");
    }
    for (artifact, resolution) in &mut resolutions.artifacts {
        artifact_path(artifact)?;
        if let Resolution::File { path } = resolution {
            if !path.is_absolute() {
                *path = parent.join(&*path);
            }
        }
    }
    Ok(resolutions.artifacts)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportReport {
    pub format_version: u32,
    pub sources: Vec<String>,
    pub changes: Vec<ArtifactChange>,
    pub conflicts: Vec<String>,
    pub affected_questions: Vec<String>,
    pub provenance_changed: Vec<String>,
    pub no_op: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArtifactChange {
    pub path: String,
    /// add, change, delete, unchanged, customized, retained, or conflict.
    pub action: String,
    pub previous_sha256: Option<String>,
    pub current_sha256: Option<String>,
    pub next_sha256: Option<String>,
    pub accepted_sha256: Option<String>,
    pub previous_owners: Vec<String>,
    pub next_owners: Vec<String>,
    pub next_owner_sha256: BTreeMap<String, String>,
    pub resolution: Option<String>,
    pub reason: Option<String>,
}

/// A complete private candidate and the exact project snapshot it was based
/// on. Validation is supplied by the owning compiler, never by another digest
/// or evaluation implementation here.
pub(crate) struct Candidate {
    root: PathBuf,
    project: PathBuf,
    _temporary: tempfile::TempDir,
    before: BTreeMap<String, Contents>,
    after: BTreeMap<String, Contents>,
    state_before: Option<Contents>,
    state_after: Contents,
    report: ImportReport,
    validated: bool,
}

impl Candidate {
    pub(crate) fn project(&self) -> &Path {
        &self.project
    }
    pub(crate) fn report(&self) -> &ImportReport {
        &self.report
    }

    pub(crate) fn validate(&mut self, validate: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
        if !self.report.conflicts.is_empty() {
            bail!("source candidate has unresolved conflicts; choose keep, adopt, or an explicit resolved file");
        }
        validate(self.project())?;
        // The validation hook must inspect this candidate, not quietly edit it.
        if snapshot(self.project())? != self.after {
            bail!("source candidate changed during validation; prepare and validate it again");
        }
        self.validated = true;
        Ok(())
    }

    pub(crate) fn apply(self, lock: &ProjectLock) -> Result<()> {
        if !self.validated {
            bail!("source candidate must pass complete compiler validation before application");
        }
        if self.root != lock.root
            || snapshot(&lock.root)? != self.before
            || read(&lock.root, STATE_PATH, MAX_STATE_BYTES)? != self.state_before
        {
            bail!("authored project changed since source comparison; prepare and validate a fresh candidate");
        }
        if self.report.no_op {
            return Ok(());
        }
        let mut operations = Vec::new();
        for path in self
            .before
            .keys()
            .chain(self.after.keys())
            .collect::<BTreeSet<_>>()
        {
            if self.before.get(path) != self.after.get(path) {
                artifact_path(path)?;
                operations.push(Operation {
                    path: path.clone(),
                    before: self.before.get(path).cloned(),
                    after: self.after.get(path).cloned(),
                });
            }
        }
        operations.push(Operation {
            path: STATE_PATH.to_owned(),
            before: self.state_before,
            after: Some(self.state_after),
        });
        transact(lock, operations)
    }
}

pub(crate) fn prepare(
    lock: &ProjectLock,
    exports: &[PathBuf],
    resolutions: &BTreeMap<String, Resolution>,
) -> Result<Candidate> {
    if exports.is_empty() || exports.len() > 64 {
        bail!("source import requires between 1 and 64 complete local export directories");
    }
    let state_before = read(&lock.root, STATE_PATH, MAX_STATE_BYTES)?;
    let previous = parse_state(state_before.as_ref())?;
    let mut next = previous.clone();
    let mut requested = BTreeSet::new();
    let mut provenance_changed = Vec::new();
    for directory in exports {
        let mut export = load_export(directory)?;
        let id = export.manifest.source_id.clone();
        if !requested.insert(id.clone()) {
            bail!("an export sourceId appears more than once in the candidate set");
        }
        if let Some(installed) = previous.imports.get(&id) {
            if installed.detached {
                bail!("source `{id}` is detached; retain its authored fork or use a distinct sourceId");
            }
            export.retained = installed.retained.clone();
        }
        if previous
            .imports
            .get(&id)
            .map(|record| &record.manifest.provenance)
            != Some(&export.manifest.provenance)
        {
            provenance_changed.push(id.clone());
        }
        next.imports.insert(id, export);
    }
    if next.imports.len() > 64 {
        bail!("a project may track at most 64 source exports");
    }
    let old_owners = owners(&previous);
    let next_owners = owners(&next);
    let before = snapshot(&lock.root)?;
    let mut after = before.clone();
    let paths: BTreeSet<String> = old_owners
        .keys()
        .chain(next_owners.keys())
        .cloned()
        .collect();
    if resolutions.keys().any(|path| !paths.contains(path)) {
        bail!("resolution names an artifact outside the installed and candidate export set");
    }
    let mut changes = Vec::new();
    let mut conflicts = Vec::new();
    for path in paths {
        let old_owner_ids = old_owners.get(&path).cloned().unwrap_or_default();
        let next_owner_ids = next_owners.get(&path).cloned().unwrap_or_default();
        let old = consistent_upstream(&previous, &path, &old_owner_ids)?;
        let upstreams = upstream_variants(&next, &path, &next_owner_ids);
        let next_owner_sha256 = next_owner_ids
            .iter()
            .map(|owner| {
                (
                    owner.clone(),
                    digest(next.imports[owner].upstream[&path].as_bytes()),
                )
            })
            .collect();
        let current = before.get(&path).map(|content| content.text.clone());
        if upstreams.len() > 1 {
            conflicts.push(path.clone());
            changes.push(ArtifactChange {
                path,
                action: "conflict".to_owned(),
                previous_sha256: hash(&old),
                current_sha256: hash(&current),
                next_sha256: None,
                accepted_sha256: hash(&current),
                previous_owners: old_owner_ids.into_iter().collect(),
                next_owners: next_owner_ids.into_iter().collect(),
                next_owner_sha256,
                resolution: None,
                reason: Some(
                    "shared owners export different bytes; update every affected owner together"
                        .to_owned(),
                ),
            });
            continue;
        }
        let upstream = upstreams.into_iter().next();
        let collision =
            old.is_none() && current.is_some() && !previous.accepted.contains_key(&path);
        let retained_by_fork = previous.imports.values().any(|record| {
            (record.detached && record.upstream.contains_key(&path))
                || record.retained.contains_key(&path)
        });
        let conflicting = collision
            || (old != upstream && current != old && current != upstream)
            || (retained_by_fork && current != upstream && old != upstream);
        let resolution = resolutions.get(&path);
        let (accepted, resolution_name) = match resolution {
            Some(Resolution::Keep) => (current.clone(), Some("keep".to_owned())),
            Some(Resolution::Adopt) => (upstream.clone(), Some("adopt".to_owned())),
            Some(Resolution::File { path }) => {
                (Some(read_resolution(path)?), Some("file".to_owned()))
            }
            None if conflicting => {
                conflicts.push(path.clone());
                (current.clone(), None)
            }
            None if old == upstream => (current.clone(), None),
            None => (upstream.clone(), None),
        };
        if let Some(text) = &accepted {
            after.insert(
                path.clone(),
                Contents {
                    text: text.clone(),
                    mode: before.get(&path).map_or(0o600, |content| content.mode),
                },
            );
        } else {
            after.remove(&path);
        }
        let action = if conflicting && resolution.is_none() {
            "conflict"
        } else if current == accepted && accepted != upstream {
            "customized"
        } else {
            change_kind(&current, &accepted)
        };
        changes.push(ArtifactChange {
            path: path.clone(), action: action.to_owned(), previous_sha256: hash(&old), current_sha256: hash(&current), next_sha256: hash(&upstream), accepted_sha256: hash(&accepted),
            previous_owners: old_owner_ids.iter().cloned().collect(), next_owners: next_owner_ids.iter().cloned().collect(), next_owner_sha256, resolution: resolution_name,
            reason: if collision { Some("destination already contains an authored artifact; explicitly keep or adopt ownership".to_owned()) }
                else if retained_by_fork && conflicting { Some("a detached source or retained authored artifact still uses this path; explicitly review its resolution".to_owned()) }
                else { None },
        });
        next.accepted.insert(path.clone(), accepted.clone());
        if collision && matches!(resolution, Some(Resolution::Keep)) {
            for id in &next_owner_ids {
                if let Some(text) = &upstream {
                    let record = next.imports.get_mut(id).expect("candidate owner exists");
                    record.retained.insert(
                        path.clone(),
                        RetainedArtifact {
                            upstream: text.clone(),
                            provenance: record.manifest.provenance.clone(),
                        },
                    );
                }
            }
        }
        if matches!(resolution, Some(Resolution::Adopt)) {
            for id in &next_owner_ids {
                next.imports
                    .get_mut(id)
                    .expect("candidate owner exists")
                    .retained
                    .remove(&path);
            }
        }
        for id in &old_owner_ids {
            let record = next
                .imports
                .get_mut(id)
                .expect("installed owners remain in state");
            if !record.upstream.contains_key(&path) && accepted.is_some() {
                if let Some(old) = &old {
                    record.retained.insert(
                        path.clone(),
                        RetainedArtifact {
                            upstream: old.clone(),
                            provenance: previous.imports[id].manifest.provenance.clone(),
                        },
                    );
                }
            }
        }
    }
    // Keep a formerly generated artifact if another ordinary authored document
    // still names it. This conservative check never rewrites that document.
    loop {
        let mut retained_any = false;
        for change in &mut changes {
            if change.action != "delete" || !has_reference(&after, &change.path)? {
                continue;
            }
            retained_any = true;
            let content = before
                .get(&change.path)
                .expect("a deletion had current content")
                .clone();
            next.accepted
                .insert(change.path.clone(), Some(content.text.clone()));
            after.insert(change.path.clone(), content);
            change.action = "retained".to_owned();
            change.accepted_sha256 = change.current_sha256.clone();
            change.reason = Some("an authored reference still needs this artifact".to_owned());
            for owner in &change.previous_owners {
                if let Some(old) = previous.imports[owner].upstream.get(&change.path) {
                    next.imports
                        .get_mut(owner)
                        .expect("owner remains recorded")
                        .retained
                        .insert(
                            change.path.clone(),
                            RetainedArtifact {
                                upstream: old.clone(),
                                provenance: previous.imports[owner].manifest.provenance.clone(),
                            },
                        );
                }
            }
        }
        if !retained_any {
            break;
        }
    }
    let state_after = encode_state(&next)?;
    let no_op = before == after && previous == next;
    let affected_questions = affected_questions(&before, &after, &changes)?;
    let temporary_root = fs::canonicalize(std::env::temp_dir())
        .context("resolving private source candidate temporary parent")?;
    let temporary = tempfile::Builder::new()
        .prefix("evidence-source-candidate-")
        .tempdir_in(&temporary_root)?;
    let project =
        fs::canonicalize(temporary.path()).context("resolving private source candidate project")?;
    for (path, content) in &after {
        write(&project, path, Some(content))?;
    }
    Ok(Candidate {
        root: lock.root.clone(),
        project,
        _temporary: temporary,
        before,
        after,
        state_before,
        state_after,
        report: ImportReport {
            format_version: 1,
            sources: requested.into_iter().collect(),
            changes,
            conflicts,
            affected_questions,
            provenance_changed,
            no_op,
        },
        validated: false,
    })
}

/// Forking changes only ownership state. Files and their import provenance are
/// retained, and future source updates explicitly refuse this source identity.
pub(crate) fn detach(lock: &ProjectLock, source_id: &str) -> Result<()> {
    let before = read(&lock.root, STATE_PATH, MAX_STATE_BYTES)?;
    let mut state = parse_state(before.as_ref())?;
    let installed = state
        .imports
        .get_mut(source_id)
        .ok_or_else(|| anyhow!("source `{source_id}` has no imported baseline"))?;
    if installed.detached {
        return Ok(());
    }
    installed.detached = true;
    for path in installed.upstream.keys().chain(installed.retained.keys()) {
        state.accepted.insert(
            path.clone(),
            read(&lock.root, path, MAX_FILE_BYTES)?.map(|content| content.text),
        );
    }
    transact(
        lock,
        vec![Operation {
            path: STATE_PATH.to_owned(),
            before,
            after: Some(encode_state(&state)?),
        }],
    )
}

fn load_export(directory: &Path) -> Result<InstalledExport> {
    let root = files::plain_directory(directory)?;
    let content = read(&root, MANIFEST_FILE, MAX_FILE_BYTES)?
        .ok_or_else(|| anyhow!("local export is missing source-export.json"))?;
    let mut manifest: ExportManifest = serde_json::from_str(&content.text)
        .context("source export must use the closed Version 1 manifest")?;
    if manifest.format_version != 1 || !valid_local_identifier(&manifest.source_id) {
        bail!("source export requires formatVersion 1 and a stable lowercase sourceId");
    }
    if manifest.provenance.is_empty()
        || manifest.provenance.len() > 32
        || manifest.provenance.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 64
                || value.is_empty()
                || value.len() > 2048
                || key.chars().chain(value.chars()).any(char::is_control)
        })
    {
        bail!("export provenance must be a bounded map of nonempty printable strings");
    }
    if manifest.artifacts.is_empty() || manifest.artifacts.len() > MAX_ARTIFACTS {
        bail!("a source export must inventory between 1 and 256 artifacts");
    }
    manifest
        .artifacts
        .sort_by(|left, right| left.path.cmp(&right.path));
    let mut upstream = BTreeMap::new();
    let mut bytes = 0;
    for artifact in &manifest.artifacts {
        artifact_path(&artifact.path)?;
        if artifact.sha256.len() != 64
            || !artifact
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("export checksums must be lowercase hexadecimal SHA-256");
        }
        let content = read(&root, &artifact.path, MAX_FILE_BYTES)?
            .ok_or_else(|| anyhow!("export inventory artifact is absent: {}", artifact.path))?;
        bytes += content.text.len();
        if bytes > MAX_EXPORT_BYTES {
            bail!("source export exceeds its 16 MiB artifact bound");
        }
        if digest(content.text.as_bytes()) != artifact.sha256 {
            bail!(
                "export artifact checksum does not match its inventory: {}",
                artifact.path
            );
        }
        if artifact.path.ends_with(".yaml") {
            let value: Value = serde_norway::from_str(&content.text)
                .context("export artifact is not YAML or JSON")?;
            if !value.is_object() {
                bail!("export source, selector, and schema artifacts must be objects");
            }
        }
        if upstream
            .insert(artifact.path.clone(), content.text)
            .is_some()
        {
            bail!("export inventory contains a duplicate artifact path");
        }
    }
    if !upstream.contains_key(&format!("sources/{}.yaml", manifest.source_id))
        || upstream
            .keys()
            .filter(|path| path.starts_with("sources/"))
            .count()
            != 1
    {
        bail!(
            "one export must inventory exactly sources/<sourceId>.yaml and its auxiliary artifacts"
        );
    }
    Ok(InstalledExport {
        manifest,
        upstream,
        retained: BTreeMap::new(),
        detached: false,
    })
}

fn parse_state(content: Option<&Contents>) -> Result<State> {
    let Some(content) = content else {
        return Ok(State::default());
    };
    let state: State =
        serde_json::from_str(&content.text).context("parsing the source-import baseline")?;
    if state.format_version != 1 || state.imports.len() > 64 {
        bail!("source-import baseline has an unsupported version or exceeds its bound");
    }
    for (id, installed) in &state.imports {
        if id != &installed.manifest.source_id
            || !valid_local_identifier(id)
            || installed.manifest.format_version != 1
        {
            bail!("source-import baseline has inconsistent source identity");
        }
        for path in installed.upstream.keys().chain(installed.retained.keys()) {
            artifact_path(path)?;
        }
        for artifact in &installed.manifest.artifacts {
            let text = installed
                .upstream
                .get(&artifact.path)
                .ok_or_else(|| anyhow!("source-import baseline is missing upstream content"))?;
            if digest(text.as_bytes()) != artifact.sha256 {
                bail!("source-import baseline upstream checksum is inconsistent");
            }
        }
    }
    for path in state.accepted.keys() {
        artifact_path(path)?;
    }
    Ok(state)
}

fn encode_state(state: &State) -> Result<Contents> {
    let text = serde_json::to_string_pretty(state)? + "\n";
    if text.len() as u64 > MAX_STATE_BYTES {
        bail!("source-import baseline exceeds its byte bound");
    }
    Ok(Contents { text, mode: 0o600 })
}

fn owners(state: &State) -> BTreeMap<String, BTreeSet<String>> {
    let mut owners: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (id, installed) in &state.imports {
        if !installed.detached {
            for path in installed.upstream.keys() {
                owners.entry(path.clone()).or_default().insert(id.clone());
            }
        }
    }
    owners
}

fn upstream_variants(state: &State, path: &str, owners: &BTreeSet<String>) -> BTreeSet<String> {
    owners
        .iter()
        .map(|owner| state.imports[owner].upstream[path].clone())
        .collect()
}

fn consistent_upstream(
    state: &State,
    path: &str,
    owners: &BTreeSet<String>,
) -> Result<Option<String>> {
    let variants = upstream_variants(state, path, owners);
    if variants.len() > 1 {
        bail!("installed shared source artifact baseline is inconsistent");
    }
    Ok(variants.into_iter().next())
}

fn read_resolution(path: &Path) -> Result<String> {
    let parent = files::plain_directory(
        path.parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("resolved file needs a UTF-8 name"))?;
    Ok(read(&parent, name, MAX_FILE_BYTES)?
        .ok_or_else(|| anyhow!("explicitly resolved file is absent"))?
        .text)
}

fn hash(text: &Option<String>) -> Option<String> {
    text.as_ref().map(|text| digest(text.as_bytes()))
}
fn change_kind(before: &Option<String>, after: &Option<String>) -> &'static str {
    if before == after {
        "unchanged"
    } else if before.is_none() {
        "add"
    } else if after.is_none() {
        "delete"
    } else {
        "change"
    }
}

fn references(value: &Value, path: &str, stem: &str) -> bool {
    match value {
        Value::String(value) => value == path || value == stem,
        Value::Array(values) => values.iter().any(|value| references(value, path, stem)),
        Value::Object(values) => values.values().any(|value| references(value, path, stem)),
        _ => false,
    }
}

fn has_reference(artifacts: &BTreeMap<String, Contents>, path: &str) -> Result<bool> {
    let stem = Path::new(path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(path);
    for (name, content) in artifacts {
        if name != path && name.ends_with(".yaml") {
            let value: Value = serde_norway::from_str(&content.text)
                .with_context(|| format!("reading authored references in {name}"))?;
            if references(&value, path, stem) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn affected_questions(
    before: &BTreeMap<String, Contents>,
    after: &BTreeMap<String, Contents>,
    changes: &[ArtifactChange],
) -> Result<Vec<String>> {
    let mut changed = BTreeSet::new();
    for change in changes {
        if change.current_sha256 != change.accepted_sha256 || change.action == "conflict" {
            changed.insert(change.path.clone());
            for owner in change.previous_owners.iter().chain(&change.next_owners) {
                changed.insert(format!("sources/{owner}.yaml"));
            }
        }
    }
    // Follow exact authored references to a fixed point. This labels structural
    // dependants only, never fabricates a runtime requirement revision.
    loop {
        let count = changed.len();
        for (path, content) in before.iter().chain(after) {
            if path.ends_with(".yaml") && !changed.contains(path) {
                let value: Value = serde_norway::from_str(&content.text)
                    .with_context(|| format!("reading structural source impact in {path}"))?;
                if changed.iter().any(|dependency| {
                    references(
                        &value,
                        dependency,
                        Path::new(dependency)
                            .file_stem()
                            .and_then(|value| value.to_str())
                            .unwrap_or(dependency),
                    )
                }) {
                    changed.insert(path.clone());
                }
            }
        }
        if changed.len() == count {
            break;
        }
    }
    Ok(changed
        .into_iter()
        .filter_map(|path| {
            path.strip_prefix("questions/")
                .and_then(|name| name.strip_suffix(".yaml"))
                .map(str::to_owned)
        })
        .collect())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    path: String,
    before: Option<Contents>,
    after: Option<Contents>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    format_version: u32,
    operations: Vec<Operation>,
}

fn transact(lock: &ProjectLock, operations: Vec<Operation>) -> Result<()> {
    for operation in &operations {
        if read(&lock.root, &operation.path, authored_bound(&operation.path))? != operation.before {
            bail!("source-import content precondition changed immediately before application");
        }
    }
    files::ensure_state_directory(&lock.root)?;
    let journal = Journal {
        format_version: 1,
        operations,
    };
    let text = serde_json::to_string(&journal)?;
    if text.len() as u64 > MAX_JOURNAL_BYTES {
        bail!("source-import transaction exceeds its byte bound");
    }
    write(
        &lock.root,
        JOURNAL_PATH,
        Some(&Contents { text, mode: 0o600 }),
    )?;
    let result = (|| {
        for operation in &journal.operations {
            if read(&lock.root, &operation.path, authored_bound(&operation.path))?
                != operation.before
            {
                bail!("authored artifact changed during source application; recovery preserves the independent edit");
            }
            write(&lock.root, &operation.path, operation.after.as_ref())?;
        }
        for operation in &journal.operations {
            if read(&lock.root, &operation.path, authored_bound(&operation.path))?
                != operation.after
            {
                bail!("authored artifact changed before source application committed");
            }
        }
        // Imports can create the first sources/selectors/schemas/adapters
        // directory. Persist those root entries before committing their state.
        files::sync_directory(&lock.root)?;
        // Unlinking the durable journal is the commit point. Before it, recovery
        // rolls back every complete file replacement, including the baseline.
        fs::remove_file(lock.root.join(JOURNAL_PATH))?;
        files::sync_directory(&lock.root.join(".evidence/source-imports"))
    })();
    if let Err(error) = result {
        recover(lock).context("recovering an interrupted source-import transaction")?;
        return Err(error);
    }
    Ok(())
}

fn recover(lock: &ProjectLock) -> Result<()> {
    if !files::validate_recovery_state(&lock.root)? {
        return Ok(());
    }
    let Some(content) = read(&lock.root, JOURNAL_PATH, MAX_JOURNAL_BYTES)? else {
        return Ok(());
    };
    let journal: Journal =
        serde_json::from_str(&content.text).context("reading source-import recovery journal")?;
    if journal.format_version != 1 || journal.operations.len() > files::MAX_PROJECT_FILES + 1 {
        bail!("source-import recovery journal has an unsupported version or bound");
    }
    let mut paths = BTreeSet::new();
    for operation in &journal.operations {
        if operation.path != STATE_PATH {
            artifact_path(&operation.path)?;
        }
        if !paths.insert(&operation.path) {
            bail!("source-import recovery journal repeats an artifact");
        }
        let current = read(&lock.root, &operation.path, authored_bound(&operation.path))?;
        if current != operation.before && current != operation.after {
            bail!("source-import recovery found an independent edit to {}; preserve it, restore the recorded before or after content, and retry", operation.path);
        }
    }
    // Check the entire journal first. A conflict never causes partial rollback.
    for operation in journal.operations.iter().rev() {
        write(&lock.root, &operation.path, operation.before.as_ref())?;
    }
    fs::remove_file(lock.root.join(JOURNAL_PATH))?;
    files::sync_directory(&lock.root.join(".evidence/source-imports"))
}

#[cfg(test)]
mod tests;
