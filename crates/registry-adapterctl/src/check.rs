// SPDX-License-Identifier: Apache-2.0

//! `adapterctl check`: the offline authoring check over one adapter
//! project, the profile and pack it pins, its fixture suites, and with
//! `--runtime` the operator runtime configuration too, whose `${NAME}`
//! expressions `--environment` fills from the process environment
//! (`products/adapter/CONCEPT.md` sections 6, 8.1, and 13.3).
//!
//! The command reads every file, verifies the digest pins of the pack's
//! script and query-file inventory (CFG-EMBED-1), verifies the versions
//! and digests the project pins for its profile and pack against the
//! artifacts as read (CFG-ID-4), precompiles the pack's Rhai entrypoints,
//! checks each fixture entry's expected facade response against the schema
//! its expected status selects (the operation's derived result schema for a
//! 2xx status, the profile's derived problem envelope for any other), and
//! composes the pure
//! checks of `registry-adapter-core` (never re-implements them). It is
//! offline: no network, no database, no execution of a checked route or
//! script.
//!
//! The command reads the authored artifacts through one reader,
//! `registry-platform-yaml`, refusing environment expressions where they
//! are written (CFG-SEC-2), and the runtime configuration through the
//! shared loader, `registry-platform-config`, the way the served runtime
//! reads it; the generated schemas are held to these by this crate's
//! tests, never by a second validation beside the authoring check.

use clap::Args;
use registry_adapter_core::{
    check_fixture_expected_response, check_project_pins, check_workspace,
    derive_operation_result_schema, derive_problem_envelope_schema, finding, script_references,
    CheckCode, ScriptSite, Workspace, ADAPTER_FIXTURE_API_VERSION, ADAPTER_FIXTURE_KIND,
    ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND, ADAPTER_PROFILE_API_VERSION, ADAPTER_PROFILE_KIND,
    ADAPTER_PROJECT_API_VERSION, ADAPTER_PROJECT_KIND, ADAPTER_RUNTIME_API_VERSION,
    ADAPTER_RUNTIME_KIND,
};
use registry_platform_config::{
    sha256_uri, AuthoredExpressions, RuntimeConfigLoader, RuntimeEnvelope, DEFAULT_STAND_IN,
};
use registry_platform_script::rhai::{
    compile_entrypoint, RhaiBaseEngine, RhaiCompileError, RhaiLimits, RhaiProfile,
};
use registry_platform_yaml::{
    ApiVersion, Decoded, Diagnostic, Digest, EnvelopeRule, Expect, FormatSpec, Reader, Report,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

/// The engine contract a pack's Rhai entrypoints must compile under: the
/// platform authoring shape, the limits every maintained runtime profile
/// publishes (CFG-EMBED-1's compile half).
const SCRIPT_PROFILE: RhaiProfile = RhaiProfile {
    limits: RhaiLimits {
        operations: 100_000,
        call_levels: 32,
        expression_depth: 64,
        modules: 0,
        string_bytes: 16_384,
        array_items: 256,
        map_entries: 256,
    },
    base: RhaiBaseEngine::Standard,
    disabled_symbols: &["import", "export", "eval", "print", "debug"],
    allow_anonymous_fn: false,
    maximum_source_bytes: 65_536,
};

/// The authored project format, derived per CFG-ENV-2 and CFG-ENV-3 from the
/// core naming constants.
pub(crate) const PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROJECT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The authored profile format.
pub(crate) const PROFILE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROFILE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROFILE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The authored pack format.
pub(crate) const PACK_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PACK_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PACK_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The fixture suite format.
pub(crate) const FIXTURE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_FIXTURE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_FIXTURE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Authored adapter project: its directory (holding `project.yaml`) or
    /// the `project.yaml` file itself. The profile, pack, and fixtures are
    /// read beside the project either way.
    #[arg(value_name = "PROJECT")]
    pub project: PathBuf,

    /// Exit 1 when a warning is reported.
    #[arg(long)]
    pub deny_warnings: bool,

    /// Operator runtime configuration file checked with the project.
    #[arg(long, value_name = "FILE")]
    pub runtime: Option<PathBuf>,

    /// Read the environment when checking the runtime configuration:
    /// `${NAME}` expressions are filled from the process environment and
    /// every value is checked. Without it, each expression is checked by
    /// syntax and position only.
    #[arg(long, requires = "runtime")]
    pub environment: bool,

    /// Profile file read instead of the `profile.yaml` beside the project.
    #[arg(long, value_name = "FILE")]
    pub profile: Option<PathBuf>,

    /// Pack file read instead of the `pack.yaml` beside the project.
    #[arg(long, value_name = "FILE")]
    pub pack: Option<PathBuf>,

    /// Fixture file read instead of the `fixtures/` directory beside the
    /// project; repeatable, and each given file replaces the whole set.
    #[arg(long, value_name = "FILE")]
    pub fixtures: Vec<PathBuf>,
}

/// Why the check could not run to a verdict.
pub(crate) enum CheckFailure {
    /// A required file could not be read: the environment is broken, not the
    /// authoring.
    Io { path: String, source: io::Error },
}

/// One run's verdict: the findings collected over every file read, how many
/// files were read, and the project path as given.
pub(crate) struct CheckRun {
    pub diagnostics: Vec<Diagnostic>,
    pub files_checked: usize,
    pub project: String,
}

/// Check one project. Reads every file even after a refusal so one pass
/// names everything to fix; a document that does not read stops the run
/// only when the file itself is unavailable.
pub(crate) fn run(args: &CheckArgs) -> Result<CheckRun, CheckFailure> {
    let mut report = Report::new(Vec::new());
    let mut files = 0usize;

    // The project may be given as its directory or as its `project.yaml`;
    // every other artifact is read beside the project either way.
    let (project_path, directory) = resolve_project(&args.project);
    let project = read::<registry_adapter_core::AdapterProject>(
        &project_path,
        &PROJECT_FORMAT,
        &mut report,
        &mut files,
    )?;
    let profile_path = args
        .profile
        .clone()
        .unwrap_or_else(|| directory.join("profile.yaml"));
    let profile = read::<registry_adapter_core::AdapterProfile>(
        &profile_path,
        &PROFILE_FORMAT,
        &mut report,
        &mut files,
    )?;
    let pack_path = args
        .pack
        .clone()
        .unwrap_or_else(|| directory.join("pack.yaml"));
    let pack = read::<registry_adapter_core::AdapterPack>(
        &pack_path,
        &PACK_FORMAT,
        &mut report,
        &mut files,
    )?;

    let fixture_paths = if args.fixtures.is_empty() {
        discovered_fixtures(&directory)?
    } else {
        args.fixtures.clone()
    };
    let mut fixtures = Vec::new();
    for path in &fixture_paths {
        if let Some((decoded, _)) = read::<registry_adapter_core::AdapterFixture>(
            path,
            &FIXTURE_FORMAT,
            &mut report,
            &mut files,
        )? {
            fixtures.push(decoded.value);
        }
    }

    let runtime = match &args.runtime {
        Some(path) => read_runtime(path, args.environment, &mut report, &mut files)?,
        None => None,
    };

    // A document the reader refuses stops the composition: the pure checks
    // need parsed values. The run still reports everything the reader found.
    if report.has_errors() {
        return Ok(CheckRun {
            diagnostics: report.into_diagnostics(),
            files_checked: files,
            project: project_string(&args.project),
        });
    }

    let (project_decoded, _) = project.expect("the project decoded");
    let (profile_decoded, profile_bytes) = profile.expect("the profile decoded");
    let (pack_decoded, pack_bytes) = pack.expect("the pack decoded");
    let project = project_decoded.value;
    let profile = profile_decoded.value;
    let pack = pack_decoded.value;

    let pinned = verify_digest_pins(&pack, &pack_path, &mut report, &mut files)?;
    verify_entrypoints(&pack, &pack_path, &pinned, &mut report);
    verify_query_files(&pack, &pack_path, &pinned, &mut report);
    verify_graphql_operations(&pack, &pack_path, &pinned, &mut report);
    verify_project_pins(
        &project,
        &profile,
        &profile_bytes,
        &pack,
        &pack_bytes,
        &mut report,
    );

    // Compose the core's pure checks over the parsed workspace.
    let workspace = Workspace {
        profile: &profile,
        pack: &pack,
        project: &project,
        runtime: runtime.as_ref(),
        fixtures: &fixtures,
    };
    for diagnostic in check_workspace(&workspace) {
        report.push(diagnostic);
    }
    check_fixture_bodies(&profile, &project, &fixtures, &mut report);

    Ok(CheckRun {
        diagnostics: report.into_diagnostics(),
        files_checked: files,
        project: project_string(&args.project),
    })
}

fn project_string(path: &Path) -> String {
    path.display().to_string()
}

/// Resolve the project argument: a directory means `project.yaml` inside
/// it, anything else is the `project.yaml` path itself. The pair is
/// (project file, directory beside which every other artifact lives).
pub(crate) fn resolve_project(project: &Path) -> (PathBuf, PathBuf) {
    if project.is_dir() {
        let directory = project.to_path_buf();
        (directory.join("project.yaml"), directory)
    } else {
        let directory = project.parent().map(Path::to_path_buf).unwrap_or_default();
        (project.to_path_buf(), directory)
    }
}

/// Read and decode one document, folding a reader refusal into `report` and
/// counting the file as checked either way. `None` means the reader refused.
/// The bytes come back with the decode so the pin checks hash the file as
/// read, not a second read of it.
/// One read's outcome: the decoded document with the bytes it was read
/// from, or `None` when the reader refused the document.
type DecodedFile<T> = Option<(Decoded<T>, Vec<u8>)>;

pub(crate) fn read<T: serde::de::DeserializeOwned>(
    path: &Path,
    format: &FormatSpec<'static>,
    report: &mut Report,
    files: &mut usize,
) -> Result<DecodedFile<T>, CheckFailure> {
    let shown = path.display().to_string();
    let bytes = std::fs::read(path).map_err(|source| CheckFailure::Io {
        path: shown.clone(),
        source,
    })?;
    *files += 1;
    // Authored files are reviewed and packaged as written: an environment
    // expression in one is refused where it is written, never filled
    // (CFG-SEC-2). Substitution belongs to the operator runtime, which this
    // command reads through the shared loader instead.
    let mut hook = AuthoredExpressions;
    let decoded = Reader::new(shown)
        .with_hook(&mut hook)
        .decode::<T>(&bytes, &Expect::one(format));
    match decoded {
        Ok(decoded) => {
            for warning in decoded.document.warnings().into_diagnostics() {
                report.push(warning);
            }
            Ok(Some((decoded, bytes)))
        }
        Err(refused) => {
            report.extend(refused);
            Ok(None)
        }
    }
}

/// Read and decode the operator runtime configuration the way the runtime
/// reads it: through the shared loader, whose envelope, byte, and path rules
/// the served runtime also enforces (CFG-CHECK-1). With `substitute`,
/// `${NAME}` expressions are filled from the process environment and every
/// value is checked; without it, each expression is checked by syntax and
/// position only, and a value it would fill is replaced whole by a stand-in
/// so the members around it still decode. A file the loader cannot read is
/// an environment failure; one it refuses is reported.
fn read_runtime(
    path: &Path,
    substitute: bool,
    report: &mut Report,
    files: &mut usize,
) -> Result<Option<registry_adapter_core::AdapterRuntimeConfig>, CheckFailure> {
    let shown = path.display().to_string();
    // The loader reads absolute paths whose components are no symbolic
    // link; the canonical form of the path as given satisfies that rule on
    // aliased directories and keeps every reported position on the file the
    // caller named.
    let absolute = std::fs::canonicalize(path).map_err(|source| CheckFailure::Io {
        path: shown.clone(),
        source,
    })?;
    let loader = RuntimeConfigLoader::new(RuntimeEnvelope {
        api_version: ADAPTER_RUNTIME_API_VERSION,
        kind: ADAPTER_RUNTIME_KIND,
    });
    let check = loader.check_offline::<registry_adapter_core::AdapterRuntimeConfig>(
        &absolute,
        substitute,
        |_| DEFAULT_STAND_IN,
    );
    *files += 1;
    // Every finding names the file as the loader read it; the report names
    // files the way the caller gave them, so the path is rewritten back.
    let named = absolute.display().to_string();
    let rewrite = |diagnostic: &Diagnostic| {
        let mut diagnostic = diagnostic.clone();
        if let Some(source) = &mut diagnostic.source {
            if source.file == named {
                source.file.clone_from(&shown);
            }
        }
        for related in &mut diagnostic.related {
            if related.file == named {
                related.file.clone_from(&shown);
            }
        }
        diagnostic
    };
    if check.unavailable {
        // The loader's own finding names what refused the read; the command
        // reports it as the environment failure every other unreadable file
        // takes.
        let reason = check
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == registry_platform_config::UNAVAILABLE_CODE)
            .map(|diagnostic| diagnostic.message.clone())
            .unwrap_or_else(|| "the runtime configuration could not be read".to_owned());
        return Err(CheckFailure::Io {
            path: shown,
            source: io::Error::other(reason),
        });
    }
    for diagnostic in &check.diagnostics {
        report.push(rewrite(diagnostic));
    }
    Ok(check.loaded.map(|loaded| loaded.config))
}

/// The fixture files of a project directory, in file-name order. A missing
/// `fixtures/` directory means no fixtures; a directory that cannot be
/// read is an environment failure, never a silently empty fixture set.
pub(crate) fn discovered_fixtures(directory: &Path) -> Result<Vec<PathBuf>, CheckFailure> {
    let fixtures = directory.join("fixtures");
    let entries = match std::fs::read_dir(&fixtures) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(CheckFailure::Io {
                path: fixtures.display().to_string(),
                source,
            })
        }
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| CheckFailure::Io {
            path: fixtures.display().to_string(),
            source,
        })?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "yaml")
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

/// Verify every script and query-file inventory entry against the bytes on
/// disk beside the pack document (CFG-EMBED-1). A missing or altered file
/// refuses with the pack's digest-pin code; the pack is incomplete as
/// authored, which is a refusal, not an environment failure. Returns the
/// bytes each read accepted, so the entrypoint compile reuses one read.
fn verify_digest_pins(
    pack: &registry_adapter_core::AdapterPack,
    pack_path: &Path,
    report: &mut Report,
    files: &mut usize,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, CheckFailure> {
    let mut pinned = BTreeMap::new();
    let mut counted: BTreeSet<PathBuf> = BTreeSet::new();
    verify_inventory(
        &pack.scripts,
        "/scripts",
        pack_path,
        &mut counted,
        &mut pinned,
        report,
        files,
    )?;
    verify_inventory(
        &pack.query_files,
        "/queryFiles",
        pack_path,
        &mut counted,
        &mut pinned,
        report,
        files,
    )?;
    Ok(pinned)
}

/// Verify one inventory list. A file two entries name is still read once,
/// so the file count stays the count of files actually read.
#[allow(clippy::too_many_arguments)]
fn verify_inventory(
    entries: &registry_platform_yaml::UniqueList<registry_adapter_core::ScriptReference>,
    pointer: &str,
    pack_path: &Path,
    counted: &mut BTreeSet<PathBuf>,
    pinned: &mut BTreeMap<PathBuf, Vec<u8>>,
    report: &mut Report,
    files: &mut usize,
) -> Result<(), CheckFailure> {
    for (index, script) in entries.iter().enumerate() {
        let path = pack_path
            .parent()
            .map(|directory| directory.join(&script.path))
            .unwrap_or_else(|| PathBuf::from(&script.path));
        let pointer = format!("{pointer}/{index}");
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                report.push(pin_finding(
                    pack_path,
                    &pointer,
                    "the pinned file is missing",
                    &script.path,
                ));
                continue;
            }
        };
        if counted.insert(path.clone()) {
            *files += 1;
        }
        if sha256_uri(&bytes) != script.digest.as_str() {
            report.push(pin_finding(
                pack_path,
                &pointer,
                "the file does not hash to its digest pin",
                &script.path,
            ));
        }
        pinned.insert(path, bytes);
    }
    Ok(())
}

/// Compile every Rhai entrypoint the pack's routes and route templates
/// reference, over the bytes the digest pins accepted (CFG-EMBED-1). Core
/// owns the exhaustive walk ([`script_references`]); a site whose file the
/// pins refused is already reported there and compiles nowhere.
fn verify_entrypoints(
    pack: &registry_adapter_core::AdapterPack,
    pack_path: &Path,
    pinned: &BTreeMap<PathBuf, Vec<u8>>,
    report: &mut Report,
) {
    let directory = pack_path.parent();
    let resolve = |file: &str| match directory {
        Some(directory) => directory.join(file),
        None => PathBuf::from(file),
    };
    for site in script_references(pack) {
        let bytes = match pinned.get(&resolve(&site.file)) {
            Some(bytes) => bytes,
            None => continue,
        };
        let source = match std::str::from_utf8(bytes) {
            Ok(source) => source,
            Err(_) => {
                report.push(uncompilable_finding(
                    pack_path,
                    &site,
                    "the pinned script is not UTF-8 text",
                    None,
                ));
                continue;
            }
        };
        match compile_entrypoint(
            &SCRIPT_PROFILE,
            source,
            &site.entrypoint,
            &[site.role.arity()],
        ) {
            Ok(_) => {}
            Err(RhaiCompileError::SourceBound) => {
                report.push(uncompilable_finding(
                    pack_path,
                    &site,
                    "the script exceeds the compile source bound",
                    None,
                ));
            }
            Err(RhaiCompileError::Parse(position)) => {
                let position = (position.line(), position.position());
                report.push(uncompilable_finding(
                    pack_path,
                    &site,
                    "the script does not parse",
                    Some(position),
                ));
            }
            Err(RhaiCompileError::Entrypoint) => {
                report.push(uncompilable_finding(
                    pack_path,
                    &site,
                    "the script does not declare exactly one public function under the entrypoint name at the parameter count the slot calls it with",
                    None,
                ));
            }
        }
    }
}

/// Parse every query-file inventory entry the pack pins (CFG-ID-6). A
/// file no GraphQL parser accepts refuses at its inventory entry; the
/// parser's own message quotes the document, so the finding carries only
/// a fixed description and the file's location (CFG-SEC-3). A file the
/// digest pins refused is already reported there and parses nowhere.
fn verify_query_files(
    pack: &registry_adapter_core::AdapterPack,
    pack_path: &Path,
    pinned: &BTreeMap<PathBuf, Vec<u8>>,
    report: &mut Report,
) {
    let directory = pack_path.parent();
    let resolve = |file: &str| match directory {
        Some(directory) => directory.join(file),
        None => PathBuf::from(file),
    };
    for (index, file) in pack.query_files.iter().enumerate() {
        let parses = pinned
            .get(&resolve(&file.path))
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|source| graphql_parser::parse_query::<&str>(source).ok())
            .is_some();
        if parses {
            continue;
        }
        let mut diagnostic = finding(
            CheckCode::PackGraphQlQueryInvalid,
            &format!("/queryFiles/{index}"),
            "the pinned query file does not parse as a GraphQL document",
            "Repair the query file beside the pack so it parses as a GraphQL document, or update its digest pin.",
        );
        diagnostic.source = Some(registry_platform_yaml::Source {
            file: format!("{} ({})", pack_path.display(), file.path),
            line: None,
            column: None,
        });
        report.push(diagnostic);
    }
}

/// Verify every graphql endpoint's named operation against the operations
/// its pinned query file declares (CFG-ID-6). Each file parses once; a
/// file that does not parse is already refused at its inventory entry.
/// The kind the endpoint operation declares against the file stays with
/// the core model checks; this command owns the file's own text.
fn verify_graphql_operations(
    pack: &registry_adapter_core::AdapterPack,
    pack_path: &Path,
    pinned: &BTreeMap<PathBuf, Vec<u8>>,
    report: &mut Report,
) {
    let directory = pack_path.parent();
    let resolve = |file: &str| match directory {
        Some(directory) => directory.join(file),
        None => PathBuf::from(file),
    };
    let mut declared: BTreeMap<&str, Option<Vec<&str>>> = BTreeMap::new();
    for file in pack.query_files.iter().map(|file| file.path.as_str()) {
        if declared.contains_key(file) {
            continue;
        }
        let names = pinned
            .get(&resolve(file))
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|source| graphql_parser::parse_query::<&str>(source).ok())
            .map(document_operations);
        declared.insert(file, names);
    }
    for (index, endpoint) in pack.endpoints.iter().enumerate() {
        if endpoint.component != registry_adapter_core::ComponentKind::GraphQl {
            continue;
        }
        let (Some(operation_name), Some(query_file)) =
            (&endpoint.operation_name, &endpoint.query_file)
        else {
            continue;
        };
        let Some(Some(names)) = declared.get(query_file.as_str()) else {
            continue;
        };
        if names.contains(&operation_name.as_str()) {
            continue;
        }
        let mut diagnostic = finding(
            CheckCode::PackGraphQlOperationUnknown,
            &format!("/endpoints/{index}/operationName"),
            "the endpoint names an operation its query file does not declare",
            "Name an operation the endpoint's query file declares, or declare the operation in the file.",
        );
        diagnostic.source = Some(registry_platform_yaml::Source {
            file: pack_path.display().to_string(),
            line: None,
            column: None,
        });
        report.push(diagnostic);
    }
}

/// The names of the named operations a parsed query document declares.
/// Anonymous selection sets and fragment definitions name no operation
/// and match nothing.
fn document_operations<'a>(document: graphql_parser::query::Document<'a, &'a str>) -> Vec<&'a str> {
    let mut names = Vec::new();
    for definition in &document.definitions {
        match definition {
            graphql_parser::query::Definition::Operation(
                graphql_parser::query::OperationDefinition::Query(operation),
            ) => names.extend(operation.name),
            graphql_parser::query::Definition::Operation(
                graphql_parser::query::OperationDefinition::Mutation(operation),
            ) => names.extend(operation.name),
            graphql_parser::query::Definition::Operation(
                graphql_parser::query::OperationDefinition::Subscription(operation),
            ) => names.extend(operation.name),
            graphql_parser::query::Definition::Operation(
                graphql_parser::query::OperationDefinition::SelectionSet(_),
            )
            | graphql_parser::query::Definition::Fragment(_) => {}
        }
    }
    names
}

/// The compile finding for one script site. The message names the rule,
/// never a file's contents (CFG-SEC-3).
fn uncompilable_finding(
    pack_path: &Path,
    site: &ScriptSite,
    message: &str,
    position: Option<(Option<usize>, Option<usize>)>,
) -> Diagnostic {
    let mut diagnostic = finding(
        CheckCode::PackScriptUncompilable,
        &site.path,
        message,
        "Repair the script beside the pack so it parses and declares exactly one public entrypoint function at the parameter count the slot calls it with.",
    );
    diagnostic.source = Some(registry_platform_yaml::Source {
        file: format!("{} ({})", pack_path.display(), site.file),
        line: position.and_then(|(line, _)| line),
        column: position.and_then(|(_, column)| column),
    });
    diagnostic
}

/// The digest-pin finding for one inventory entry. The message names the
/// rule and the inventory path, never a file's contents (CFG-SEC-3).
fn pin_finding(pack_path: &Path, pointer: &str, message: &str, script_path: &str) -> Diagnostic {
    let mut diagnostic = finding(
        CheckCode::PackDigestPinRequired,
        pointer,
        message,
        "Restore the file beside the pack document, or update its sha256 digest pin.",
    );
    diagnostic.source = Some(registry_platform_yaml::Source {
        file: format!("{} ({script_path})", pack_path.display()),
        line: None,
        column: None,
    });
    diagnostic
}

/// Verify the versions and digests the project pins for its profile and
/// pack against the artifacts as read (CFG-ID-4). Core owns the
/// comparison; this command owns the hashing of the bytes it already read.
fn verify_project_pins(
    project: &registry_adapter_core::AdapterProject,
    profile: &registry_adapter_core::AdapterProfile,
    profile_bytes: &[u8],
    pack: &registry_adapter_core::AdapterPack,
    pack_bytes: &[u8],
    report: &mut Report,
) {
    for diagnostic in check_project_pins(
        project,
        &profile.version,
        &digest_of(profile_bytes),
        &pack.version,
        &digest_of(pack_bytes),
    ) {
        report.push(diagnostic);
    }
}

/// The sha256 digest of one artifact's bytes, in the pinned uri form.
pub(crate) fn digest_of(bytes: &[u8]) -> Digest {
    Digest::new(sha256_uri(bytes)).expect("a computed sha256 uri is a valid digest")
}

/// Check every fixture entry's expected facade response body against the
/// schema its expected status selects: the operation's derived result
/// schema for a 2xx status, the profile's derived problem envelope for any
/// other (CONCEPT 6). A problem expectation carries no body: its class and
/// code resolve in the core fixture checks. Core owns the derivation and
/// the check; a derivation fault is already reported by the workspace
/// check, so an entry whose schema cannot derive checks no body here.
pub(crate) fn check_fixture_bodies(
    profile: &registry_adapter_core::AdapterProfile,
    project: &registry_adapter_core::AdapterProject,
    fixtures: &[registry_adapter_core::AdapterFixture],
    report: &mut Report,
) {
    // The workspace check derives every envelope once (core's
    // check_envelope_derivation) and reports each derivation fault as a
    // named adapter.profile finding, so the entry check runs only over
    // schemas that derived, never over a stand-in that would invent
    // findings. An expected status of 2xx validates against the operation's
    // result schema, any other against the profile's problem envelope, and
    // the selection is the core check's.
    let problem = derive_problem_envelope_schema(profile);
    for fixture in fixtures {
        for (entry_index, entry) in fixture.entries.iter().enumerate() {
            let is_result = match &entry.expected {
                registry_adapter_core::ExpectedFacade::Response { status, .. } => {
                    (200..=299).contains(&status.get())
                }
                registry_adapter_core::ExpectedFacade::Problem { .. } => continue,
            };
            let result_schema = match derive_operation_result_schema(
                profile,
                project,
                entry.facade_request.operation.as_str(),
            ) {
                Ok(schema) => schema,
                Err(_) => continue,
            };
            if !is_result && problem.is_err() {
                continue;
            }
            // A 2xx expected status never consults the problem schema; the
            // never-true stand-in keeps one call site while the envelope has
            // not derived.
            let stand_in = Value::Bool(false);
            let problem_schema = problem.as_ref().unwrap_or(&stand_in);
            for diagnostic in check_fixture_expected_response(
                entry_index,
                &entry.expected,
                &result_schema,
                problem_schema,
            ) {
                report.push(diagnostic);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Reader agreement (CFG-YAML-1 in spirit): every authored artifact
    /// this crate's fixture corpus carries decodes through the platform
    /// reader as its own type, the way `check` reads it, and satisfies the
    /// generated schema of its kind. The command itself runs one reader;
    /// this test is where the generator is held to it. Decoding is per
    /// kind, not through a plain `Value`: a fixture's recorded body opens
    /// the reader's foreign-value region, where the explicit `null` a
    /// recorded exchange may carry is a body, and only the type's own
    /// decode accepts it.
    #[test]
    fn the_generated_schemas_accept_what_the_reader_decodes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal");
        let cases: [(&str, &FormatSpec<'static>, &str); 4] = [
            (
                "project.yaml",
                &PROJECT_FORMAT,
                "project.v1alpha1.schema.json",
            ),
            (
                "profile.yaml",
                &PROFILE_FORMAT,
                "profile.v1alpha1.schema.json",
            ),
            ("pack.yaml", &PACK_FORMAT, "pack.v1alpha1.schema.json"),
            (
                "fixtures/records.yaml",
                &FIXTURE_FORMAT,
                "fixture.v1alpha1.schema.json",
            ),
        ];
        let generated = crate::schemas::documents().expect("the schemas generate");
        for (file, format, schema_file) in cases {
            let bytes = std::fs::read(root.join(file)).expect("the corpus file exists");
            let reader = Reader::new(file.to_owned());
            let document = match file {
                "project.yaml" => reader
                    .decode::<registry_adapter_core::AdapterProject>(&bytes, &Expect::one(format))
                    .map(|decoded| decoded.document),
                "profile.yaml" => reader
                    .decode::<registry_adapter_core::AdapterProfile>(&bytes, &Expect::one(format))
                    .map(|decoded| decoded.document),
                "pack.yaml" => reader
                    .decode::<registry_adapter_core::AdapterPack>(&bytes, &Expect::one(format))
                    .map(|decoded| decoded.document),
                _ => reader
                    .decode::<registry_adapter_core::AdapterFixture>(&bytes, &Expect::one(format))
                    .map(|decoded| decoded.document),
            }
            .unwrap_or_else(|refused| panic!("{file}: {}", refused.render_human()));
            let schema: Value = serde_json::from_str(
                generated
                    .get(schema_file)
                    .expect("the generator produces every kind's schema"),
            )
            .expect("the generated schema is JSON");
            let validator = jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .compile(&schema)
                .expect("the generated schema compiles");
            let errors: Vec<String> = validator
                .validate(&document.to_json_value())
                .err()
                .map(|errors| errors.map(|error| error.to_string()).collect())
                .unwrap_or_default();
            assert!(errors.is_empty(), "{file}: {errors:?}");
        }
    }
}
