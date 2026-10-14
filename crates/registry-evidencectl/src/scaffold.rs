//! Minimal Evidence project authoring from OpenAPI, a local starter, or a SQLite extract.
//!
//! `new` retains an API description for a later question-authoring step, or
//! creates a runnable synthetic starter around one fixed statement. The
//! starter is an editable example, not a deployment policy or production
//! extract.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context as _, Result};
use clap::{ArgGroup, Args, ValueEnum};

use crate::{authored, keygen, suggest, tooling_editor, OutputFormat};
use serde_json::json;

const RETAINED_OPENAPI_FILE: &str = "source.openapi.yaml";
const MAX_STARTER_FILES: usize = 512;
const MAX_STARTER_BYTES: usize = 16 * 1024 * 1024;
const MAX_STARTER_FILE_BYTES: u64 = 1024 * 1024;
const STARTER_TOP_LEVEL_FILES: &[&str] = &[
    "README.md",
    "evidence.yaml",
    "local-target.yaml",
    "dev-authority.yaml",
    "serve-source.py",
];
const STARTER_DIRECTORIES: &[&str] = &["functions", "fixtures", "codelists", "queries"];

#[derive(Clone, Debug, ValueEnum)]
pub enum AuthoringProfile {
    /// Development-only authoring with no deployment assurance claim.
    Local,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AuthoringTransport {
    /// Author a fixed statement over a published SQLite extract.
    SqliteExtract,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("authoring_source")
        .required(true)
        .multiple(false)
        .args(["openapi", "transport", "starter"])
))]
pub struct NewArgs {
    /// New directory to create for the editable authoring project.
    pub directory: PathBuf,

    /// OpenAPI 3.0 or 3.1 document: a local path or an HTTPS URL.
    #[arg(long)]
    pub openapi: Option<String>,

    /// Source transport to author without an API description.
    #[arg(long, value_enum, conflicts_with = "openapi")]
    pub transport: Option<AuthoringTransport>,

    /// Reviewed local starter directory to copy without requiring an API description.
    #[arg(long, conflicts_with_all = ["openapi", "transport"])]
    pub starter: Option<PathBuf>,

    /// Explicit development profile for local authoring.
    #[arg(long, value_enum, required = true)]
    pub profile: Option<AuthoringProfile>,
}

pub(crate) fn run_with_format(
    args: NewArgs,
    command: &'static str,
    format: OutputFormat,
) -> anyhow::Result<ExitCode> {
    create(args, Some(command), format)
}

/// Start source-first authoring through the same staged project and key setup
/// used by `new`. There is no question until its author supplies its meaning.
pub(crate) fn create_source_project(directory: &Path) -> Result<()> {
    let starter = tempfile::tempdir().context("staging the source-first project description")?;
    write_new_file(
        &starter.path().join("README.md"),
        b"# Evidence source project\n\nThis normalized EvidenceProject can receive imported Sources and Functions. Review its AssertionDefinitions and complete source bindings before deployment. Source credentials grant no Evidence caller authority.\n",
        0o644,
    )?;
    create(
        NewArgs {
            directory: directory.to_path_buf(),
            openapi: None,
            transport: None,
            starter: Some(starter.path().to_path_buf()),
            profile: Some(AuthoringProfile::Local),
        },
        None,
        OutputFormat::Human,
    )?;
    Ok(())
}

/// Create the project; `report` names the command whose report is written,
/// and is `None` when another command creates the project on its behalf.
fn create(
    args: NewArgs,
    report: Option<&'static str>,
    format: OutputFormat,
) -> anyhow::Result<ExitCode> {
    let source = match (args.openapi.as_deref(), args.transport, args.starter.as_deref()) {
        (Some(openapi), None, None) => AuthoringSource::OpenApi(openapi),
        (None, Some(AuthoringTransport::SqliteExtract), None) => AuthoringSource::SqliteExtract,
        (None, None, Some(starter)) => AuthoringSource::Starter(starter),
        (None, None, None) => bail!(
            "pass --openapi <path-or-https-url> for API authoring, --transport sqlite-extract for extract authoring, or --starter <dir> for an offline starter"
        ),
        _ => bail!("--openapi, --transport, and --starter cannot be used together"),
    };
    if args.profile.is_none() {
        bail!(
            "{} authoring requires the explicit development profile `--profile local`",
            source.label()
        );
    }

    validate_new_destination(&args.directory)?;
    let parent = destination_parent(&args.directory)?;
    let retained_openapi = match source {
        AuthoringSource::OpenApi(openapi) => {
            let source = suggest::fetch::spec_source(openapi)?;
            let (_, document) = suggest::load::open_retained(&source)?;
            Some(document)
        }
        AuthoringSource::SqliteExtract => None,
        AuthoringSource::Starter(_) => None,
    };
    let starter_files = match source {
        AuthoringSource::Starter(starter) => collect_starter_files(starter)?,
        AuthoringSource::OpenApi(_) | AuthoringSource::SqliteExtract => Vec::new(),
    };
    let supplied_normalized_starter = validate_normalized_starter(&starter_files)?;
    // A starter that ships no source (its README asks for one to be imported
    // or authored first) cannot yet prove itself with `fixtures run`, so the
    // printed next step must defer to the starter's own README instead.
    let starter_ships_a_source = true;

    let staging = tempfile::Builder::new()
        .prefix(".evidencectl-new-")
        .tempdir_in(parent)
        .with_context(|| format!("staging the project in {}", parent.display()))?;
    let staged_root = staging.path();

    write_new_file(
        &staged_root.join(".gitignore"),
        b".generated/secrets/\n.evidence/\n",
        0o644,
    )?;
    // A project a reader can edit needs a page naming what was written and what
    // comes next, and the two authoring paths leave different things standing:
    // the starter is a working example, the retained description is an empty
    // frame around one operation not yet selected.
    if !matches!(source, AuthoringSource::Starter(_))
        || !starter_files
            .iter()
            .any(|file| file.relative == Path::new("README.md"))
    {
        write_new_file(&staged_root.join("README.md"), source.readme(), 0o644)?;
    }
    if let Some(document) = retained_openapi.as_ref() {
        write_new_file(
            &staged_root.join(RETAINED_OPENAPI_FILE),
            document.as_bytes(),
            0o644,
        )?;
    }
    for directory in ["functions", "fixtures"] {
        fs::create_dir(staged_root.join(directory))
            .with_context(|| format!("creating the empty {directory} directory"))?;
    }
    if matches!(source, AuthoringSource::SqliteExtract) {
        fs::create_dir(staged_root.join("queries"))
            .context("creating the empty queries directory")?;
    }
    for file in starter_files {
        write_new_file(&staged_root.join(file.relative), &file.contents, 0o644)?;
    }
    if !supplied_normalized_starter {
        write_normalized_starter(staged_root, source)?;
    }

    keygen::generate_scaffold_key_material(
        &staged_root.join(registry_evidence_authoring::layout::SECRETS_DIRECTORY),
    )
    .context("generating unbound local authoring key material")?;

    // Schema mappings belong to a project from its first minute, so that the
    // editor knows the normalized forms before an adopter changes them.
    // Staging is the only place this can run without a conflict check that
    // could refuse: nothing else has ever written here.
    tooling_editor::setup_project_editor(staged_root)
        .context("configuring project-local editor schema mappings")?;

    fs::set_permissions(staged_root, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("setting permissions on {}", staged_root.display()))?;
    publish(staging, &args.directory)?;

    let Some(command) = report else {
        return Ok(ExitCode::SUCCESS);
    };
    if format == OutputFormat::Json {
        crate::report::print(&crate::report::success(
            command,
            "created",
            serde_json::json!({
                "project": args.directory,
                "profile": "local",
                "proofBoundary": "project scaffold only; no authoring or deployment validation was performed"
            }),
        ))?;
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "Created an editable {} authoring project in {}",
        source.label(),
        args.directory.display()
    );
    println!(
        "  README: {} (what each file holds, and what comes next)",
        args.directory.join("README.md").display()
    );
    if matches!(source, AuthoringSource::OpenApi(_)) {
        println!(
            "  OpenAPI: {} (retained exactly for question authoring)",
            args.directory.join(RETAINED_OPENAPI_FILE).display()
        );
    }
    println!(
        "  project: {}",
        args.directory.join("evidence.yaml").display()
    );
    println!(
        "  functions: {}",
        args.directory.join("functions").display()
    );
    if matches!(source, AuthoringSource::SqliteExtract) || args.directory.join("queries").exists() {
        println!("  queries: {}", args.directory.join("queries").display());
    }
    println!(
        "  target: {}",
        args.directory.join("local-target.yaml").display()
    );
    println!(
        "  authority: {}",
        args.directory.join("dev-authority.yaml").display()
    );
    println!("  fixtures: {}", args.directory.join("fixtures").display());
    println!(
        "  keys: {} (owner-only, disposable, and unbound)",
        args.directory
            .join(registry_evidence_authoring::layout::SECRETS_DIRECTORY)
            .display()
    );
    match source {
        AuthoringSource::OpenApi(_) => println!(
            "Next: run `evidencectl source suggest {}` to draft one editable source.",
            args.directory.display()
        ),
        AuthoringSource::SqliteExtract => {
            println!(
            "Next: run `evidencectl check {}` and `evidencectl test {}` to prove the synthetic starter, then edit its source, statement, schemas, derivation, and fixtures together.",
                args.directory.display(),
                args.directory.display()
            );
        }
        AuthoringSource::Starter(_) if starter_ships_a_source => println!(
            "Next: run `evidencectl check {}` and `evidencectl test {}` to prove the copied starter before live credentials.",
            args.directory.display(),
            args.directory.display()
        ),
        AuthoringSource::Starter(_) => println!(
            "Next: follow {}/README.md; this starter ships no source, so import or author one before `evidencectl check {}` and `evidencectl test {}`.",
            args.directory.display(),
            args.directory.display(),
            args.directory.display()
        ),
    }
    match source {
        AuthoringSource::OpenApi(_) => println!(
            "A normalized synthetic starter and local target were generated beside the retained OpenAPI document. Review or replace the starter Source and AssertionDefinition."
        ),
        AuthoringSource::SqliteExtract => println!(
            "A normalized synthetic Source, AssertionDefinition, and local target were generated. No production extract or deployment bundle was generated."
        ),
        AuthoringSource::Starter(starter) => println!(
            "Starter files were copied from {} and combined with the normalized project and local target. No production extract or deployment bundle was imported.",
            starter.display()
        ),
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Clone, Copy)]
enum AuthoringSource<'a> {
    OpenApi(&'a str),
    SqliteExtract,
    Starter(&'a Path),
}

impl AuthoringSource<'_> {
    fn label(self) -> &'static str {
        match self {
            Self::OpenApi(_) => "OpenAPI",
            Self::SqliteExtract => "SQLite-extract",
            Self::Starter(_) => "starter",
        }
    }

    fn readme(self) -> &'static [u8] {
        match self {
            Self::OpenApi(_) => include_bytes!("../templates/openapi/README.md"),
            Self::SqliteExtract => include_bytes!("../templates/sqlite-extract/README.md"),
            Self::Starter(_) => include_bytes!("../templates/starter/README.md"),
        }
    }
}

fn validate_new_destination(path: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "refusing to replace existing project path {}; choose a new directory",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("inspecting project path {}", path.display()))
        }
    }
}

struct StarterFile {
    relative: PathBuf,
    contents: Vec<u8>,
}

fn collect_starter_files(root: &Path) -> Result<Vec<StarterFile>> {
    let root = plain_directory(root, "starter directory")?;
    let mut files = Vec::new();
    let mut bytes = 0usize;
    for file in STARTER_TOP_LEVEL_FILES {
        let path = root.join(file);
        if path.exists() {
            push_starter_file(&root, Path::new(file), &mut files, &mut bytes)?;
        }
    }
    for directory in STARTER_DIRECTORIES {
        let path = root.join(directory);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                collect_starter_directory(&root, Path::new(directory), 0, &mut files, &mut bytes)?;
            }
            Ok(_) => bail!("starter entries must be plain files or directories"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspecting starter directory {}", path.display()));
            }
        }
    }
    if files.is_empty() {
        bail!("starter directory contains no ordinary Evidence starter files");
    }
    files.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(files)
}

/// Distinguish a complete normalized starter from a source-first starter.
/// A complete starter is preserved byte for byte, but must prove that its
/// project, target, and complete authority agree before any destination is
/// created. A README-and-assets starter receives the synthetic normalized
/// project below.
fn validate_normalized_starter(files: &[StarterFile]) -> Result<bool> {
    let find = |name: &str| {
        files
            .iter()
            .find(|file| file.relative == Path::new(name))
            .map(|file| file.contents.as_slice())
    };
    let Some(project_bytes) = find("evidence.yaml") else {
        if find("local-target.yaml").is_some() || find("dev-authority.yaml").is_some() {
            bail!("a normalized starter must supply evidence.yaml, local-target.yaml, and dev-authority.yaml together");
        }
        return Ok(false);
    };
    let target_bytes = find("local-target.yaml")
        .context("a normalized starter with evidence.yaml must also supply local-target.yaml")?;
    let authority_bytes = find("dev-authority.yaml")
        .context("a normalized starter with evidence.yaml must also supply dev-authority.yaml")?;
    let project =
        registry_evidence_authoring::project::read_project("evidence.yaml", project_bytes)?.value;
    let target =
        registry_evidence_authoring::target::read_target("local-target.yaml", target_bytes)?.value;
    if target.project != project.id || target.authority != "dev-authority.yaml" {
        bail!("the starter local-target.yaml must name its EvidenceProject and dev-authority.yaml");
    }
    let authority = registry_evidence_authoring::target::read_authority(
        "dev-authority.yaml",
        authority_bytes,
        &project,
    )?
    .value;
    if authority.target != target.id || authority.project != project.id {
        bail!("the starter dev-authority.yaml must name its EvidenceTarget and EvidenceProject");
    }
    Ok(true)
}

fn collect_starter_directory(
    root: &Path,
    relative: &Path,
    depth: usize,
    files: &mut Vec<StarterFile>,
    bytes: &mut usize,
) -> Result<()> {
    if depth > 16 {
        bail!("starter file nesting is too deep");
    }
    for entry in fs::read_dir(root.join(relative))
        .with_context(|| format!("reading starter directory {}", relative.display()))?
    {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("starter file names must be UTF-8"))?;
        if name.starts_with('.') {
            bail!("starter files must not be hidden control files");
        }
        let child = relative.join(name);
        let metadata = fs::symlink_metadata(root.join(&child))
            .with_context(|| format!("inspecting starter file {}", child.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("starter files must not be symbolic links");
        }
        if metadata.is_dir() {
            collect_starter_directory(root, &child, depth + 1, files, bytes)?;
        } else if metadata.is_file() {
            push_starter_file(root, &child, files, bytes)?;
        } else {
            bail!("starter entries must be plain files or directories");
        }
    }
    Ok(())
}

fn push_starter_file(
    root: &Path,
    relative: &Path,
    files: &mut Vec<StarterFile>,
    bytes: &mut usize,
) -> Result<()> {
    if !starter_relative_path(relative) {
        bail!("starter files must stay in ordinary Evidence authoring directories");
    }
    if files.len() >= MAX_STARTER_FILES {
        bail!("starter directory contains too many files");
    }
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspecting starter file {}", relative.display()))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_STARTER_FILE_BYTES
    {
        bail!("starter files must be bounded plain files");
    }
    let contents =
        fs::read(&path).with_context(|| format!("reading starter file {}", relative.display()))?;
    if contents.len() as u64 > MAX_STARTER_FILE_BYTES {
        bail!("starter file exceeds its byte limit");
    }
    *bytes = bytes
        .checked_add(contents.len())
        .ok_or_else(|| anyhow::anyhow!("starter file byte count overflowed"))?;
    if *bytes > MAX_STARTER_BYTES {
        bail!("starter directory exceeds its byte limit");
    }
    files.push(StarterFile {
        relative: relative.to_path_buf(),
        contents,
    });
    Ok(())
}

fn starter_relative_path(relative: &Path) -> bool {
    let text = relative.to_string_lossy();
    if text.is_empty() || text.contains('\\') {
        return false;
    }
    let mut components = relative.components();
    let Some(std::path::Component::Normal(first)) = components.next() else {
        return false;
    };
    let Some(first) = first.to_str() else {
        return false;
    };
    if STARTER_TOP_LEVEL_FILES.contains(&first) {
        return components.next().is_none();
    }
    STARTER_DIRECTORIES.contains(&first)
        && components.all(|component| match component {
            std::path::Component::Normal(part) => part
                .to_str()
                .is_some_and(|part| !part.is_empty() && part != "." && part != ".."),
            _ => false,
        })
}

fn destination_parent(path: &Path) -> anyhow::Result<&Path> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspecting project parent {}", parent.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "project parent {} must be an existing plain directory",
            parent.display()
        );
    }
    Ok(parent)
}

fn plain_directory(path: &Path, description: &str) -> Result<PathBuf> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspecting {description}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{description} must be an existing plain directory");
    }
    fs::canonicalize(path).with_context(|| format!("resolving {description}"))
}

fn write_new_file(path: &Path, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::{fs::OpenOptions, io::Write as _, os::unix::fs::OpenOptionsExt as _};

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("persisting {}", path.display()))
}

fn write_normalized_starter(root: &Path, source: AuthoringSource<'_>) -> anyhow::Result<()> {
    let sqlite = matches!(source, AuthoringSource::SqliteExtract);
    let source_document = if sqlite {
        json!({
            "type": "sqlite-extract",
            "acquisitionPosture": "record-transformed",
            "selectors": [{"role":"subject","profiles":["record-reference"]}],
            "request": {
                "statement":"queries/record-status.sql",
                "columns":[{"name":"qualifying_record_count","type":"integer"}],
                "parameterBindings":{"record_reference":{"selector":{"role":"subject","profile":"record-reference","field":"record-reference"}}},
                "maximumRows":2,
                "maximumCellBytes":64,
                "maximumStatementSteps":100000
            },
            "response": {
                "projection":["/rows/*/qualifying_record_count"],
                "shape":{"type":"object","required":["rows"],"properties":{"rows":{"type":"array","minItems":0,"maxItems":2,"items":{"type":"object","required":["qualifying_record_count"],"properties":{"qualifying_record_count":{"type":"bounded-integer","minimum":0,"maximum":1000000}}}}}},
                "maximumBytes":8192
            },
            "extract":{"function":"extract-record-status"},
            "facts":{"record-count":{"type":"bounded-integer","minimum":0,"maximum":1000000}},
            "limits":{"attemptTimeoutMilliseconds":2000,"maximumConcurrency":8},
            "extractProfile":"record-status",
            "maximumExtractAgeSeconds":604800
        })
    } else {
        json!({
            "type":"http-json",
            "connection":"starter-source",
            "acquisitionPosture":"record-transformed",
            "selectors":[{"role":"subject","profiles":["record-reference"]}],
            "request":{
                "method":"GET",
                "path":"/records/{record-reference}",
                "pathBindings":{"record-reference":{"selector":{"role":"subject","profile":"record-reference","field":"record-reference"}}},
                "fixedHeaders":[{"name":"Accept","value":"application/json"}]
            },
            "response":{
                "projection":["/matched"],
                "shape":{"type":"object","required":["matched"],"properties":{"matched":{"type":"boolean"}}},
                "maximumBytes":4096
            },
            "extract":{"function":"extract-record-status"},
            "facts":{"matched":{"type":"boolean"}},
            "limits":{"attemptTimeoutMilliseconds":2000,"maximumConcurrency":8}
        })
    };
    let project = json!({
        "apiVersion": registry_evidence_authoring::project::PROJECT_API_VERSION,
        "kind": registry_evidence_authoring::project::PROJECT_KIND,
        "id":"local-evidence",
        "selectorProfiles":{"record-reference":{"maximumAggregateBytes":64,"fields":{"record-reference":{"type":"string","minimumBytes":1,"maximumBytes":64}}}},
        "functions":[
            {"id":"extract-record-status","interface":"source-extract/v1","source":"functions/extract-record-status.rhai"},
            {"id":"derive-record-status","interface":"assertion-derive/v1","source":"functions/derive-record-status.rhai"}
        ],
        "sources":{"record-status":source_document},
        "assertionDefinitions":{"record-status":{
            "question":"Does the selected synthetic record satisfy the reviewed condition?",
            "semantics":{"requirement":"urn:example:requirement:record-status:v1","kind":"criterion","evidenceType":"urn:example:evidence-type:record-status:v1","referenceFrameworks":["urn:example:framework:record-status:v1"]},
            "purpose":"record-status-check",
            "grantCeiling":{"authorities":["organizational"],"actorKinds":["service"],"valueOrigins":["request"],"audiences":["urn:example:audience:local-evidence"]},
            "subjects":[{"role":"subject","selectors":["record-reference"]}],
            "acquisition":{"type":"single","source":"record-status"},
            "derive":{"function":"derive-record-status"},
            "outputs":{"satisfied":{"concept":"urn:example:concept:record-status:v1","type":"boolean"}},
            "validitySeconds":300,
            "subjectBinding":"audience-scoped",
            "representations":["signed-jws"]
            ,"fixtures":"fixtures/record-status.yaml"
        }}
    });
    let project_yaml = authored::to_indented_yaml(&project)?;
    registry_evidence_authoring::project::read_project("evidence.yaml", project_yaml.as_bytes())
        .context("validating the generated normalized EvidenceProject")?;
    write_new_file(&root.join("evidence.yaml"), project_yaml.as_bytes(), 0o644)?;

    let extract = if sqlite {
        include_str!("../templates/sqlite-extract/functions/extract-record-status.rhai")
    } else {
        "fn extract(source_response, context) {\n    #{outcome: \"match\", facts: #{matched: source_response[\"matched\"]}}\n}\n"
    };
    let derive = if sqlite {
        include_str!("../templates/sqlite-extract/functions/derive-record-status.rhai")
    } else {
        "fn derive(facts, selectors, context) {\n    [#{output: \"satisfied\", value: facts[\"matched\"]}]\n}\n"
    };
    write_new_file(
        &root.join("functions/extract-record-status.rhai"),
        extract.as_bytes(),
        0o644,
    )?;
    write_new_file(
        &root.join("functions/derive-record-status.rhai"),
        derive.as_bytes(),
        0o644,
    )?;
    let fixture = if sqlite {
        include_str!("../templates/sqlite-extract/fixtures/record-status.yaml")
    } else {
        r#"apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1
kind: EvidenceFixture
syntheticOnly: true
coequalAcceptanceDefinition: true
common:
  observedAt: '2026-01-01T00:00:00Z'
  selectors:
    subject:
      profile: record-reference
      values: {record-reference: REC-0001}
cases:
- id: positive
  source: {matched: true}
  expectedValue: true
  expectedLookup: match
  derivationRuns: true
  signedSuccess: true
- id: negative
  source: {matched: false}
  expectedValue: false
  expectedLookup: match
  derivationRuns: true
  signedSuccess: true
privacyExpectation:
  evidenceContains: [urn:example:concept:record-status:v1]
  evidenceExcludes: [record-reference, REC-0001]
  diagnosticsExclude: [REC-0001]
"#
    };
    let fixture_path = root.join("fixtures/record-status.yaml");
    if !fixture_path.exists() {
        write_new_file(&fixture_path, fixture.as_bytes(), 0o644)?;
    }
    if sqlite {
        write_new_file(
            &root.join("queries/record-status.sql"),
            include_bytes!("../templates/sqlite-extract/queries/record-status.sql"),
            0o644,
        )?;
    }

    let target = json!({
        "apiVersion": registry_evidence_authoring::target::TARGET_API_VERSION,
        "kind": registry_evidence_authoring::target::TARGET_KIND,
        "id":"local", "project":"local-evidence", "package":{"root":".generated/package"},
        "authority":"dev-authority.yaml",
        "service":{"providerId":"urn:example:provider:local-evidence","issuer":"urn:example:issuer:local-evidence","publicOrigin":"http://127.0.0.1:8080","trustDomain":"urn:example:trust:local-evidence"},
        "listener":{"bind":"127.0.0.1:8080","trustProxyIdentityHeaders":false},
        "authentication":{"oidc":{"issuer":"http://127.0.0.1:8081","audience":"urn:example:audience:local-evidence","tokenTypes":["at+jwt"],"algorithms":["ES256"],"jwksSource":{"type":"uri","uri":"http://127.0.0.1:8081/oauth2/jwks"},"principalClaim":"sub","requesterTagsClaim":"evidence_tags","evidenceAudienceClaim":"evidence_audience","requiredScopes":["evidence:request"],"maximumTokenLifetimeSeconds":300}},
        "connections":{"starter-source":{"origin":"http://127.0.0.1:4010","authentication":{"type":"none"}}},
        "secretProviders":{"file":{"root":".generated/secrets"}},
        "signer":{"type":"local-jwk","algorithm":"ES256","privateKeyRef":"secret:file/signing-p256-private-jwk","publicJwkFile":".generated/secrets/signing-p256-public.jwk.json"},
        "subjectBinding":{"secretRef":"secret:file/subject-binding-hmac-key","keyVersion":1},
        "audit":{"path":".generated/audit/evidence.jsonl","hashKeyRef":"secret:file/audit-hmac-key","hashKeyVersion":1},
        "rateLimits":{"requestsPerPrincipalPerMinute":60,"burstPerPrincipal":16,"failedSelectorAttemptsPerPrincipalAuthorityPerMinute":10},
        "outboundTls":{"systemRoots":true,"trustProfiles":{}}
    });
    let target_yaml = authored::to_indented_yaml(&target)?;
    registry_evidence_authoring::target::read_target("local-target.yaml", target_yaml.as_bytes())
        .context("validating the generated local EvidenceTarget")?;
    write_new_file(
        &root.join("local-target.yaml"),
        target_yaml.as_bytes(),
        0o644,
    )?;

    let authority = json!({
        "apiVersion":registry_evidence_authoring::target::AUTHORITY_API_VERSION,
        "kind":registry_evidence_authoring::target::AUTHORITY_KIND,
        "target":"local", "project":"local-evidence",
        "accessProfiles":{"local-service":{"authority":"organizational","actorKind":"service","requesterTags":["local-service"],"grants":[{"definition":"record-status","purpose":"record-status-check","audienceFrom":"authenticated-requester","representations":["signed-jws"],"subjectBinding":"audience-scoped","subjects":[{"role":"subject","selectorProfile":"record-reference","valueOrigin":"request"}]}]}}
    });
    let authority_yaml = authored::to_indented_yaml(&authority)?;
    let project = registry_evidence_authoring::project::read_project(
        "evidence.yaml",
        project_yaml.as_bytes(),
    )?
    .value;
    registry_evidence_authoring::target::read_authority(
        "dev-authority.yaml",
        authority_yaml.as_bytes(),
        &project,
    )
    .context("validating the generated local target authority")?;
    write_new_file(
        &root.join("dev-authority.yaml"),
        authority_yaml.as_bytes(),
        0o644,
    )
}

fn publish(staging: tempfile::TempDir, destination: &Path) -> anyhow::Result<()> {
    let staged = staging.keep();
    if let Err(error) = rename_noreplace(&staged, destination) {
        let _ = fs::remove_dir_all(&staged);
        return Err(error).with_context(|| {
            format!(
                "publishing the project without replacing {}",
                destination.display()
            )
        });
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn rename_noreplace(_source: &Path, _destination: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace project publication is unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_starter_documents_use_only_normalized_envelopes() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("functions")).unwrap();
        fs::create_dir(root.path().join("fixtures")).unwrap();
        fs::create_dir(root.path().join("codelists")).unwrap();
        fs::create_dir(root.path().join("queries")).unwrap();
        write_normalized_starter(root.path(), AuthoringSource::SqliteExtract).unwrap();

        let project = fs::read_to_string(root.path().join("evidence.yaml")).unwrap();
        let target = fs::read_to_string(root.path().join("local-target.yaml")).unwrap();
        let authority = fs::read_to_string(root.path().join("dev-authority.yaml")).unwrap();
        assert!(project.contains("kind: EvidenceProject"));
        assert!(target.contains("kind: EvidenceTarget"));
        assert!(authority.contains("kind: EvidenceTargetAuthority"));
        assert!(!project.contains("EvidenceQuestion"));
    }
}
