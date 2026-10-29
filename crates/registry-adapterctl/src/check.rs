// SPDX-License-Identifier: Apache-2.0

//! `adapterctl check`: the offline authoring check over one adapter
//! project, the profile and pack it pins, its fixture suites, and with
//! `--runtime` the operator runtime configuration too
//! (`products/adapter/CONCEPT.md` sections 6, 8.1, and 13.3).
//!
//! The command reads every file, verifies the digest pins of the pack's
//! script and query-file inventory (CFG-EMBED-1), and composes the pure
//! checks of `registry-adapter-core` (never re-implements them). It is
//! offline: no network, no database, no execution of a checked route or
//! script.
//!
//! The command runs one reader, `registry-platform-yaml`; the generated
//! schemas are held to it by this crate's tests, never by a second
//! validation beside the authoring check.

use clap::Args;
use registry_adapter_core::{
    check_workspace, finding, script_references, CheckCode, ScriptSite, Workspace,
    ADAPTER_FIXTURE_API_VERSION, ADAPTER_FIXTURE_KIND, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND,
    ADAPTER_PROFILE_API_VERSION, ADAPTER_PROFILE_KIND, ADAPTER_PROJECT_API_VERSION,
    ADAPTER_PROJECT_KIND, ADAPTER_RUNTIME_API_VERSION, ADAPTER_RUNTIME_KIND,
};
use registry_platform_config::sha256_uri;
use registry_platform_script::rhai::{
    compile_entrypoint, RhaiBaseEngine, RhaiCompileError, RhaiLimits, RhaiProfile,
};
use registry_platform_yaml::{
    ApiVersion, Decoded, Diagnostic, EnvelopeRule, Expect, FormatSpec, Reader, Report,
};
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
const PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROJECT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The authored profile format.
const PROFILE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROFILE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROFILE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The authored pack format.
const PACK_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PACK_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PACK_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The fixture suite format.
const FIXTURE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_FIXTURE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_FIXTURE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The operator runtime configuration format.
const RUNTIME_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_RUNTIME_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_RUNTIME_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Authored adapter project file (a `project.yaml`).
    #[arg(value_name = "PROJECT")]
    pub project: PathBuf,

    /// Exit 1 when a warning is reported.
    #[arg(long)]
    pub deny_warnings: bool,

    /// Operator runtime configuration file checked with the project.
    #[arg(long, value_name = "FILE")]
    pub runtime: Option<PathBuf>,

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

    let project_path = args.project.clone();
    let project = read::<registry_adapter_core::AdapterProject>(
        &project_path,
        &PROJECT_FORMAT,
        &mut report,
        &mut files,
    )?;
    let directory = project_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
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
        discovered_fixtures(&directory)
    } else {
        args.fixtures.clone()
    };
    let mut fixtures = Vec::new();
    for path in &fixture_paths {
        if let Some(decoded) = read::<registry_adapter_core::AdapterFixture>(
            path,
            &FIXTURE_FORMAT,
            &mut report,
            &mut files,
        )? {
            fixtures.push(decoded.value);
        }
    }

    let runtime = match &args.runtime {
        Some(path) => read::<registry_adapter_core::AdapterRuntimeConfig>(
            path,
            &RUNTIME_FORMAT,
            &mut report,
            &mut files,
        )?
        .map(|decoded| decoded.value),
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

    let project = project.expect("the project decoded").value;
    let profile = profile.expect("the profile decoded").value;
    let pack = pack.expect("the pack decoded").value;

    let pinned = verify_digest_pins(&pack, &pack_path, &mut report, &mut files)?;
    verify_entrypoints(&pack, &pack_path, &pinned, &mut report);

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

    Ok(CheckRun {
        diagnostics: report.into_diagnostics(),
        files_checked: files,
        project: project_string(&args.project),
    })
}

fn project_string(path: &Path) -> String {
    path.display().to_string()
}

/// Read and decode one document, folding a reader refusal into `report` and
/// counting the file as checked either way. `None` means the reader refused.
fn read<T: serde::de::DeserializeOwned>(
    path: &Path,
    format: &FormatSpec<'static>,
    report: &mut Report,
    files: &mut usize,
) -> Result<Option<Decoded<T>>, CheckFailure> {
    let shown = path.display().to_string();
    let bytes = std::fs::read(path).map_err(|source| CheckFailure::Io {
        path: shown.clone(),
        source,
    })?;
    *files += 1;
    let decoded = Reader::new(shown).decode::<T>(&bytes, &Expect::one(format));
    match decoded {
        Ok(decoded) => {
            for warning in decoded.document.warnings().into_diagnostics() {
                report.push(warning);
            }
            Ok(Some(decoded))
        }
        Err(refused) => {
            report.extend(refused);
            Ok(None)
        }
    }
}

/// The fixture files of a project directory, in file-name order. A missing
/// `fixtures/` directory means no fixtures.
fn discovered_fixtures(directory: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(directory.join("fixtures"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .collect();
    paths.sort();
    paths
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
    let bodies = pack
        .routes
        .iter()
        .map(|route| route.steps.as_slice())
        .chain(
            pack.route_templates
                .iter()
                .map(|template| template.steps.as_slice()),
        );
    for body in bodies {
        for site in script_references(body) {
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
            match compile_entrypoint(&SCRIPT_PROFILE, source, &site.entrypoint, &[1]) {
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
                        "the script does not declare exactly one public function under the entrypoint name at one parameter",
                        None,
                    ));
                }
            }
        }
    }
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
        &format!("/steps{}/rhai", site.path),
        message,
        "Repair the script beside the pack so it parses and declares exactly one public entrypoint function with one parameter.",
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Reader agreement (CFG-YAML-1 in spirit): every authored artifact
    /// this crate's fixture corpus carries decodes through the platform
    /// reader and satisfies the generated schema of its kind. The command
    /// itself runs one reader; this test is where the generator is held to
    /// it.
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
            let decoded = Reader::new(file.to_owned())
                .decode::<Value>(&bytes, &Expect::one(format))
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
                .validate(&decoded.document.to_json_value())
                .err()
                .map(|errors| errors.map(|error| error.to_string()).collect())
                .unwrap_or_default();
            assert!(errors.is_empty(), "{file}: {errors:?}");
        }
    }
}
