//! The offline check behind `evidence check` (CFG-CHECK-1).
//!
//! It reads the runtime file through the shared reader, verifies and loads the
//! package the file binds as that package is found, and applies every rule the
//! runtime applies to the pair that needs no secret, network, or database.
//! Independent configuration findings accumulate as CFG-DIAG-1 diagnostics.
//! A refused source plan reports its governed artifact before resource binding
//! comparison; no message repeats a configured value (CFG-SEC-3).
//!
//! Freezing, secret material, extract capture, and runtime dependencies are
//! properties of the host the deployment runs on, not of its configuration.
//! The check leaves them to `--require-runtime-dependencies`, which runs on
//! that host.

use std::{
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};

use registry_adapter_engine::evidence::EvidenceCompileError;
use registry_platform_config::{contains_environment_expression, PackageError, PackageErrorKind};
use registry_platform_yaml::{
    escape_pointer_segment, Diagnostic, Node, NodeValue, Position, Reader, Refusal, Report,
    ScalarHook, ScalarSite, Severity, Source, MAXIMUM_DOCUMENT_BYTES,
};

use crate::{
    bundle::{
        evidence_package_limits, runtime_binding_findings, validate_ca_bundle, ArtifactFault,
        Bundle, BundleError, RuntimeBindingPlanError, MAX_CA_BUNDLE_BYTES,
    },
    config::{report_in_file, ConfigError, RuntimeConfig, MAX_CONFIG_BYTES},
};

/// The `kind` a runtime file declares, named as each runtime diagnostic's
/// artifact.
pub const RUNTIME_ARTIFACT: &str = "EvidenceRuntimeConfig";
/// The kind of the bundle document, named as the artifact of each diagnostic
/// about `evidence.yaml`.
pub const BUNDLE_ARTIFACT: &str = "EvidenceBundle";

/// The bundle document inside a package.
const BUNDLE_DOCUMENT: &str = "evidence.yaml";
/// The name a runtime file carries when a fault names it as its artifact.
const RUNTIME_DOCUMENT: &str = "runtime.yaml";
/// The command an operator runs to build or rebuild a package.
const PACKAGE_COMMAND: &str = "evidencectl package";

const BUILD_PACKAGE_ACTION: &str =
    "Build the package with `evidencectl package` and point package.root at its directory.";
const REBUILD_PACKAGE_ACTION: &str =
    "Rebuild the package with `evidencectl package` and deploy the whole directory.";

/// What one offline check found, and the bundle it loaded when the package
/// could be read.
#[derive(Debug)]
pub struct OfflineCheck {
    /// The runtime file as the command was given it.
    file: String,
    diagnostics: Vec<Diagnostic>,
    files_checked: usize,
    unavailable: bool,
    package_root: Option<PathBuf>,
    bundle: Option<Bundle>,
    /// The bundle document as the reader saw it, for positions.
    bundle_tree: Option<Node>,
}

impl OfflineCheck {
    fn new(file: String) -> Self {
        Self {
            file,
            diagnostics: Vec::new(),
            files_checked: 0,
            unavailable: false,
            package_root: None,
            bundle: None,
            bundle_tree: None,
        }
    }

    /// The bundle the runtime file binds, when the package verified and loaded.
    pub fn bundle(&self) -> Option<&Bundle> {
        self.bundle.as_ref()
    }

    /// Whether any error was reported.
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
    }

    /// Whether something the check depends on could not be read, so the
    /// check could not finish (exit 3).
    pub fn is_unavailable(&self) -> bool {
        self.unavailable
    }

    /// Every diagnostic, with the number of files the check read.
    pub fn report(&self) -> Report {
        let mut report = Report::new(self.diagnostics.clone());
        report.set_files_checked(self.files_checked.max(1));
        report
    }

    /// Append the diagnostics of a refusal another reader reported.
    pub fn extend(&mut self, report: Report) {
        self.diagnostics.extend(report.into_diagnostics());
    }

    /// Record that a dependency of the check could not be read.
    pub fn mark_unavailable(&mut self) {
        self.unavailable = true;
    }

    /// One diagnostic about the deployment as a whole, reported against the
    /// runtime file that describes it.
    pub fn push_deployment(
        &mut self,
        severity: Severity,
        code: &str,
        message: impl Into<String>,
        action: impl Into<String>,
    ) {
        let mut diagnostic = Diagnostic::error(code, "", message, action);
        diagnostic.severity = severity;
        diagnostic.artifact = Some(RUNTIME_ARTIFACT.to_owned());
        diagnostic.source = Some(source(&self.file, None));
        self.diagnostics.push(diagnostic);
    }

    /// One diagnostic about a member of the bundle document, at the member's
    /// value.
    pub fn push_bundle_member(
        &mut self,
        severity: Severity,
        code: &str,
        pointer: &str,
        message: impl Into<String>,
        action: impl Into<String>,
    ) {
        let position = self
            .bundle_tree
            .as_ref()
            .and_then(|tree| locate(tree, pointer, false));
        let mut diagnostic = Diagnostic::error(code, pointer, message, action);
        diagnostic.severity = severity;
        diagnostic.artifact = Some(BUNDLE_ARTIFACT.to_owned());
        diagnostic.source = Some(source(&self.package_file(BUNDLE_DOCUMENT), position));
        self.diagnostics.push(diagnostic);
    }

    /// One diagnostic for a value-free fault in a package artifact: the file
    /// inside the package, the path and position inside it when the fault
    /// knows them, and the fault's cause.
    pub fn push_artifact_fault(&mut self, code: &str, fault: &ArtifactFault, action: &str) {
        let schema = fault.fault();
        let message = match schema.field() {
            Some(field) => format!("{} ({field})", schema.cause()),
            None => schema.cause().to_owned(),
        };
        let action = schema.remedy().unwrap_or(action);
        let artifact = fault.artifact();
        let pointer = schema.path().map(schema_path_pointer).unwrap_or_default();
        let position = schema.location().map(|location| Position {
            line: location.line,
            column: location.column,
        });
        let (file, kind) = if artifact.is_empty() {
            (self.package_label(), None)
        } else if artifact == RUNTIME_DOCUMENT {
            (self.file.clone(), Some(RUNTIME_ARTIFACT))
        } else {
            (self.package_file(artifact), artifact_kind(artifact))
        };
        let mut diagnostic = Diagnostic::error(code, pointer, message, action);
        diagnostic.artifact = kind.map(str::to_owned);
        diagnostic.source = Some(source(&file, position));
        self.diagnostics.push(diagnostic);
    }

    /// A file inside the package, as the runtime file names the package.
    fn package_file(&self, inner: &str) -> String {
        match &self.package_root {
            Some(root) => root.join(inner).display().to_string(),
            None => inner.to_owned(),
        }
    }

    /// The package directory, as the runtime file names it.
    fn package_label(&self) -> String {
        match &self.package_root {
            Some(root) => root.display().to_string(),
            None => self.file.clone(),
        }
    }

    /// One error about the package directory as a whole, reported at the
    /// directory rather than at a member of the runtime file.
    fn push_package(&mut self, code: &str, message: impl Into<String>, action: impl Into<String>) {
        let mut diagnostic = Diagnostic::error(code, "", message, action);
        diagnostic.source = Some(source(&self.package_label(), None));
        self.diagnostics.push(diagnostic);
    }

    /// One error about a member of the runtime file.
    fn push_runtime(
        &mut self,
        layout: &Layout,
        code: &str,
        pointer: &str,
        at_key: bool,
        message: impl Into<String>,
        action: impl Into<String>,
    ) {
        let mut diagnostic = Diagnostic::error(code, pointer, message, action);
        diagnostic.artifact = Some(RUNTIME_ARTIFACT.to_owned());
        diagnostic.source = Some(source(&self.file, layout.locate(pointer, at_key)));
        self.diagnostics.push(diagnostic);
    }
}

/// Check one runtime file and the package it binds, offline.
///
/// Without `environment`, a `${...}` expression is checked by its syntax and
/// position only: no environment variable is read, and a value check that
/// would need the substituted text is skipped. With it, expressions are
/// substituted from the current environment as startup substitutes them, and
/// every value check runs.
pub fn check_runtime_file(path: &Path, environment: bool) -> OfflineCheck {
    let mut check = OfflineCheck::new(path.display().to_string());
    let bytes = match read_bounded(path, MAX_CONFIG_BYTES as u64) {
        Ok(bytes) => bytes,
        Err(_) => {
            // A runtime file that is missing was not refused: the check
            // depends on it and could not read it, so it exits 3 either way.
            check.push_deployment(
                Severity::Error,
                "evidence.runtime.unavailable",
                "the runtime file could not be read",
                "Pass --runtime-config the path of a readable runtime file.",
            );
            check.mark_unavailable();
            return check;
        }
    };
    check.files_checked = 1;

    let decoded = if environment {
        RuntimeConfig::decode_yaml_with(&bytes, |name| std::env::var(name).ok())
    } else {
        // An expression stands for itself: the reader still refuses one that
        // is malformed or written where substitution is not allowed, and the
        // value it would fill is never read.
        RuntimeConfig::decode_yaml_with(&bytes, |name| Some(format!("${{{name}}}")))
    };
    let config = match decoded {
        Ok(loaded) => loaded.config,
        Err(ConfigError::Refused(report)) if !environment => {
            push_offline_refusal(&mut check, *report, &bytes);
            return check;
        }
        Err(ConfigError::Refused(report)) => {
            check.extend(report_in_file(*report, &check.file.clone()));
            return check;
        }
        Err(other) => {
            let message = other.fault().cause();
            check.push_deployment(
                Severity::Error,
                "evidence.runtime.invalid",
                message,
                "Correct the runtime file as the message says.",
            );
            return check;
        }
    };
    let layout = Layout::scan(&check.file, &bytes);

    let package_refused = push_config_findings(&mut check, &layout, &config, !environment);

    check_ca_bundles(&mut check, &config, &layout, environment);

    if package_refused {
        return check;
    }
    if !environment && layout.substituted("/package/root") {
        check.push_runtime(
            &layout,
            "evidence.package.not-checked",
            "/package/root",
            false,
            "package.root is filled by substitution, so the package was not checked",
            "Run the check with --environment where the variable is set, so the package is checked too.",
        );
        // A warning, not an error: nothing was refused.
        if let Some(last) = check.diagnostics.last_mut() {
            last.severity = Severity::Warning;
        }
        return check;
    }
    let root = config.package.root.clone();
    check.package_root = Some(root.clone());
    let verified = match config
        .package
        .verify_package(&evidence_package_limits(), PACKAGE_COMMAND)
    {
        Ok(verified) => verified,
        Err(error) => {
            push_package_error(&mut check, &layout, &error);
            return check;
        }
    };
    check.files_checked += verified.files().count();
    let mut bundle = match Bundle::load_as_found(&root, &verified) {
        Ok(bundle) => bundle,
        Err(error) => {
            push_bundle_error(&mut check, &layout, error);
            return check;
        }
    };
    if let Err(error) = bundle.bind_target_authority(config.authority.as_ref()) {
        check.push_runtime(&layout, "evidence.authority.invalid", "/authority", false,
            error.to_string(), "Activate a valid target authority for this exact package with `evidence authority activate`.");
        return check;
    }
    check.bundle_tree = bundle.artifact(BUNDLE_DOCUMENT).and_then(|bytes| {
        Reader::new(check.package_file(BUNDLE_DOCUMENT))
            .scan(bytes)
            .ok()
            .flatten()
    });

    push_binding_findings(&mut check, &layout, &bundle, &config, !environment);
    check.bundle = Some(bundle);
    check
}

/// Check one generated runtime document against an already loaded bundle.
///
/// This is the internal authoring seam used before a candidate is published.
/// It applies the runtime's own grammar, listener, signer, secret-provider,
/// TLS, extract, and acquisition binding rules without resolving a secret,
/// opening an extract, loading activated authority, or contacting a service.
pub fn check_runtime_bindings_file(path: &Path, bundle: &Bundle) -> OfflineCheck {
    let mut check = OfflineCheck::new(path.display().to_string());
    let bytes = match read_bounded(path, MAX_CONFIG_BYTES as u64) {
        Ok(bytes) => bytes,
        Err(_) => {
            check.push_deployment(
                Severity::Error,
                "evidence.runtime.unavailable",
                "the runtime file could not be read",
                "Generate a readable runtime file from the selected Evidence target.",
            );
            check.mark_unavailable();
            return check;
        }
    };
    check.files_checked = 1;
    let config = match RuntimeConfig::decode_yaml_with(&bytes, |name| Some(format!("${{{name}}}")))
    {
        Ok(loaded) => loaded.config,
        Err(ConfigError::Refused(report)) => {
            push_offline_refusal(&mut check, *report, &bytes);
            return check;
        }
        Err(other) => {
            check.push_deployment(
                Severity::Error,
                "evidence.runtime.invalid",
                other.fault().cause(),
                "Correct the selected target as the message says.",
            );
            return check;
        }
    };
    let layout = Layout::scan(&check.file, &bytes);
    push_config_findings(&mut check, &layout, &config, true);
    push_binding_findings(&mut check, &layout, bundle, &config, true);
    check
}

/// Report the runtime's own findings about one decoded document. Findings at a
/// pointer a substitution fills are skipped when `skip_substituted` is set.
/// Returns whether any finding refused the `/package` section.
fn push_config_findings(
    check: &mut OfflineCheck,
    layout: &Layout,
    config: &RuntimeConfig,
    skip_substituted: bool,
) -> bool {
    let mut package_refused = false;
    for finding in &config.findings() {
        if skip_substituted && layout.substituted(&finding.pointer) {
            continue;
        }
        package_refused |= finding.pointer.starts_with("/package");
        check.push_runtime(
            layout,
            finding.code,
            &finding.pointer,
            finding.at_key,
            finding.message(),
            finding.action.as_str(),
        );
    }
    package_refused
}

/// Report the target binding findings between a loaded bundle and one decoded
/// runtime document, with the same substitution rule as `push_config_findings`.
fn push_binding_findings(
    check: &mut OfflineCheck,
    layout: &Layout,
    bundle: &Bundle,
    config: &RuntimeConfig,
    skip_substituted: bool,
) {
    let findings = match runtime_binding_findings(bundle, config) {
        Ok(findings) => findings,
        Err(error) => {
            push_binding_plan_error(check, layout, error);
            return;
        }
    };
    for finding in findings {
        if skip_substituted && layout.substituted(&finding.pointer) {
            continue;
        }
        let message = match finding.error.artifact_fault() {
            Some(fault) => fault.fault().cause().to_owned(),
            None => finding.error.to_string(),
        };
        check.push_runtime(
            layout,
            finding.code,
            &finding.pointer,
            false,
            message,
            finding.action,
        );
    }
}

/// Report the source-plan failures whose repair belongs to the runtime file.
/// Invalid acquisition limits already have their field diagnostics from
/// `RuntimeConfig::findings`; planning cannot compare source resources after
/// that refusal, and must not fabricate a second package error.
fn push_binding_plan_error(
    check: &mut OfflineCheck,
    layout: &Layout,
    error: RuntimeBindingPlanError,
) {
    match error {
        RuntimeBindingPlanError::Limits => {}
        RuntimeBindingPlanError::SourcePlan {
            error:
                EvidenceCompileError::StaticOperationBudgetExceeded { required, maximum },
            ..
        } => check.push_runtime(
            layout,
            "evidence.runtime.source-operation-budget-exceeded",
            "/sourceAcquisition/maximumDataOperations",
            false,
            format!(
                "a selected source route requires {required} data operations in its static worst case, above the configured maximum of {maximum}"
            ),
            format!(
                "Raise sourceAcquisition.maximumDataOperations to at least {required}, or reduce and bound the selected route's sends and retries."
            ),
        ),
        RuntimeBindingPlanError::SourcePlan {
            error: EvidenceCompileError::StaticOperationBudgetUncountable,
            ..
        } => check.push_runtime(
            layout,
            "evidence.runtime.source-operation-budget-uncountable",
            "/sourceAcquisition/maximumDataOperations",
            false,
            "a selected source route exceeds the reader's nesting or numeric count bound, so its static worst-case data-operation count cannot be derived",
            "Reduce the selected route's nesting or bounded operation multipliers, then rebuild the package.",
        ),
        other => push_bundle_error(check, layout, other.into_bundle_error()),
    }
}

/// Report a runtime file the reader refused while expressions stood for
/// themselves.
///
/// A refusal of a value an expression fills is a value check that needs the
/// substituted text, so it is skipped. Decoding stopped there, so the members
/// after it and the package were not checked either, and a warning says so.
/// A refusal of the expression itself (its syntax, or a position where
/// substitution is not allowed) is kept, as is a refusal of its type:
/// substitution fills text only, so a member that is not text refuses it
/// whatever the environment holds. Every refusal elsewhere is kept too.
fn push_offline_refusal(check: &mut OfflineCheck, report: Report, bytes: &[u8]) {
    const TYPE_REFUSALS: [&str; 4] = [
        "config.expected-integer",
        "config.expected-number",
        "config.expected-boolean",
        "config.invalid-type",
    ];
    let layout = Layout::scan(&check.file, bytes);
    let mut skipped = None;
    let mut kept = Vec::new();
    for diagnostic in report_in_file(report, &check.file.clone()).into_diagnostics() {
        let value_check = !diagnostic.code.starts_with("config.substitution")
            && !TYPE_REFUSALS.contains(&diagnostic.code.as_str());
        if value_check && layout.substituted(&diagnostic.path) {
            skipped.get_or_insert(diagnostic.path);
        } else {
            kept.push(diagnostic);
        }
    }
    check.extend(Report::new(kept));
    if let Some(pointer) = skipped {
        check.push_runtime(
            &layout,
            "evidence.runtime.not-checked",
            &pointer,
            false,
            "this value is filled by substitution and could not be checked without the \
             environment, so the members after it and the package were not checked",
            "Run the check with --environment where the variables are set, so the whole file \
             and the package are checked.",
        );
        if let Some(last) = check.diagnostics.last_mut() {
            last.severity = Severity::Warning;
        }
    }
}

/// Read and validate every CA bundle a trust profile names, as found.
fn check_ca_bundles(
    check: &mut OfflineCheck,
    config: &RuntimeConfig,
    layout: &Layout,
    environment: bool,
) {
    for (profile, binding) in config.outbound_tls.trust_profiles.iter() {
        let pointer = format!(
            "/outboundTls/trustProfiles/{}/caBundleFile",
            escape_pointer_segment(profile)
        );
        if !environment && layout.substituted(&pointer) {
            continue;
        }
        let bytes = match read_bounded(Path::new(&binding.ca_bundle_file), MAX_CA_BUNDLE_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                check.push_runtime(
                    layout,
                    "evidence.runtime.ca-bundle-unavailable",
                    &pointer,
                    false,
                    "the CA bundle file the trust profile names could not be read",
                    "Place a readable PEM CA bundle at the path caBundleFile names.",
                );
                if error.kind() != std::io::ErrorKind::NotFound {
                    check.mark_unavailable();
                }
                continue;
            }
        };
        check.files_checked += 1;
        let refusal = if bytes.len() as u64 > MAX_CA_BUNDLE_BYTES {
            Some("the TLS CA bundle exceeds 1 MiB".to_owned())
        } else {
            validate_ca_bundle(&bytes).err().map(|error| match error {
                BundleError::TooLarge => {
                    "the TLS CA bundle holds more than 64 certificates".to_owned()
                }
                other => match other.artifact_fault() {
                    Some(fault) => fault.fault().cause().to_owned(),
                    None => other.to_string(),
                },
            })
        };
        if let Some(message) = refusal {
            check.push_runtime(
                layout,
                "evidence.runtime.invalid-ca-bundle",
                &pointer,
                false,
                message,
                "Write one to 64 PEM certificates, and nothing else, in the file caBundleFile names.",
            );
        }
    }
}

/// One package refusal, reported at the member of the runtime file that
/// binds the package.
fn push_package_error(check: &mut OfflineCheck, layout: &Layout, error: &PackageError) {
    let mut pointer = "/package/root";
    let (code, message, action) = match error.kind() {
        PackageErrorKind::RootInvalid { reason } => (
            "evidence.package.invalid-root",
            format!("the package directory package.root names {reason}"),
            BUILD_PACKAGE_ACTION,
        ),
        PackageErrorKind::SumFileMissing => (
            "evidence.package.sum-file-missing",
            "the directory package.root names has no SHA256SUMS, so it is not a package".to_owned(),
            BUILD_PACKAGE_ACTION,
        ),
        PackageErrorKind::SumFileInvalid { line, reason } => (
            "evidence.package.invalid-sum-file",
            format!("the package SHA256SUMS is invalid at line {line}: {reason}"),
            REBUILD_PACKAGE_ACTION,
        ),
        PackageErrorKind::Mismatch {
            changed,
            missing,
            extra,
        } => {
            let mut message = "the package does not match its SHA256SUMS".to_owned();
            for (label, paths) in [("changed", changed), ("missing", missing), ("extra", extra)] {
                if !paths.is_empty() {
                    message.push_str(&format!("; {label}: {}", paths.join(", ")));
                }
            }
            ("evidence.package.mismatch", message, REBUILD_PACKAGE_ACTION)
        }
        PackageErrorKind::UnsafeEntry { path, reason } => {
            let members = bundle_members_naming(check, path);
            if members.is_empty() {
                check.push_package(
                    "evidence.package.unsafe-entry",
                    format!("the package holds {path}, which {reason}"),
                    "Remove the entry, since a package holds only regular files, and rebuild the package with `evidencectl package`.",
                );
            }
            for member in members {
                let mut diagnostic = Diagnostic::error(
                    "evidence.package.unsafe-entry",
                    member.pointer,
                    format!("the package file this member names {reason}"),
                    "Put a regular file at this path, since a package holds only regular files, and rebuild the package with `evidencectl package`.",
                );
                diagnostic.artifact = Some(member.artifact.to_owned());
                diagnostic.source = Some(source(
                    &check.package_file(&member.document),
                    Some(member.position),
                ));
                check.diagnostics.push(diagnostic);
            }
            return;
        }
        PackageErrorKind::Bound { path, reason } => {
            if let Some(report) = path
                .as_deref()
                .and_then(|path| oversized_document(check, path))
            {
                check.extend(report);
                return;
            }
            check.push_package(
                "evidence.package.too-large",
                match path {
                    Some(path) => format!("the package is refused: {reason} ({path})"),
                    None => format!("the package is refused: {reason}"),
                },
                "Reduce the project and rebuild the package with `evidencectl package`.",
            );
            return;
        }
        PackageErrorKind::Io { path } => {
            check.mark_unavailable();
            (
                "evidence.package.unavailable",
                format!("the package file {path} could not be read"),
                "Make the package directory and its files readable by this user.",
            )
        }
        PackageErrorKind::Empty => (
            "evidence.package.empty",
            "the package holds no files".to_owned(),
            BUILD_PACKAGE_ACTION,
        ),
        PackageErrorKind::DigestMismatch(_) => {
            pointer = "/package/expectedDigest";
            (
                "evidence.package.digest-mismatch",
                "the package is not the one package.expectedDigest pins".to_owned(),
                "Write the digest `evidencectl package` printed for this package, or deploy the package the digest names.",
            )
        }
        _ => (
            "evidence.package.invalid",
            error.clone().naming_root_as("package.root").to_string(),
            REBUILD_PACKAGE_ACTION,
        ),
    };
    check.push_runtime(layout, code, pointer, false, message, action);
}

/// The shared reader's refusal of a package document over its size cap
/// (CFG-YAML-6), when the file a package bound names is a configuration
/// document: the bundle, a code list, or a fixture file. The package bound on
/// one file is the reader's cap, so the document is reported at the file with
/// the code every other format carries. `None` leaves the package refusal.
///
/// The file is opened without following a link and read to one byte past the
/// cap, so nothing outside the package is read and nothing is parsed.
fn oversized_document(check: &OfflineCheck, path: &str) -> Option<Report> {
    artifact_kind(path)?;
    let bytes = read_package_document(check, path)?;
    if bytes.len() <= MAXIMUM_DOCUMENT_BYTES {
        return None;
    }
    Reader::new(check.package_file(path)).scan(&bytes).err()
}

/// The first bytes of one package file, to one byte past the shared reader's
/// cap, read from a regular file opened without following a link. `None` when
/// the file is anything else or cannot be read.
fn read_package_document(check: &OfflineCheck, path: &str) -> Option<Vec<u8>> {
    let file = open_package_document(check, path)?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let cap = u64::try_from(MAXIMUM_DOCUMENT_BYTES).ok()?;
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

/// Open a package diagnostic document without following any directory link.
/// Verification has already refused the package, so every parent is pinned
/// independently before the bounded diagnostic read.
fn open_package_document(check: &OfflineCheck, relative: &str) -> Option<File> {
    let root = check.package_root.as_ref()?;
    let parts = Path::new(relative)
        .components()
        .map(|part| match part {
            std::path::Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let (name, parents) = parts.split_last()?;
    #[cfg(unix)]
    {
        use rustix::fs::{open, openat, Mode, OFlags};
        let directory_flags =
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY;
        let mut directory = open(root, directory_flags, Mode::empty()).ok()?;
        for parent in parents {
            directory = openat(&directory, *parent, directory_flags, Mode::empty()).ok()?;
        }
        let file = openat(
            &directory,
            *name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .ok()?;
        Some(File::from(file))
    }
    #[cfg(not(unix))]
    {
        // Optional nested diagnostics must not read through an unverified
        // parent on a platform without descriptor-relative no-follow opens.
        if !parents.is_empty() {
            return None;
        }
        crate::bundle::open_no_follow(&root.join(name)).ok()
    }
}

struct PackageMemberLocation {
    artifact: &'static str,
    document: String,
    pointer: String,
    position: Position,
}

/// Locate a refused file in the bundle or its captured Adapter pack. Pack
/// artifact pins, rather than repeated call sites, own their repair location
/// (CFG-VAL-8, CFG-DIAG-1). Missing or unreadable declarations leave the refusal
/// at the package directory.
///
/// Verification failed, so these documents are untrusted. Reads stay bounded
/// and refuse every parent link; only member positions reach diagnostics.
fn bundle_members_naming(check: &OfflineCheck, path: &str) -> Vec<PackageMemberLocation> {
    let mut locations = Vec::new();
    let bundle = read_package_document(check, BUNDLE_DOCUMENT).and_then(|bytes| {
        Reader::new(check.package_file(BUNDLE_DOCUMENT))
            .scan(&bytes)
            .ok()
            .flatten()
    });
    if let Some(tree) = bundle {
        let mut members = Vec::new();
        collect_members_naming(&tree, path, &mut String::new(), &mut members);
        locations.extend(
            members
                .into_iter()
                .map(|(pointer, position)| PackageMemberLocation {
                    artifact: BUNDLE_ARTIFACT,
                    document: BUNDLE_DOCUMENT.to_owned(),
                    pointer,
                    position,
                }),
        );
    }
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() < 4
        || parts[0] != "adapter-packs"
        || registry_platform_yaml::LocalId::new(parts[1]).is_err()
        || parts[2].len() != 64
        || !parts[2]
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return locations;
    }
    let document = format!("{}/{}/{}/pack.yaml", parts[0], parts[1], parts[2]);
    let Some(tree) = read_package_document(check, &document).and_then(|bytes| {
        Reader::new(check.package_file(&document))
            .scan(&bytes)
            .ok()
            .flatten()
    }) else {
        return locations;
    };
    if !tree.pointer("/kind").is_some_and(
        |node| matches!(&node.value, NodeValue::String(value) if value.text == "AdapterPack"),
    ) {
        return locations;
    }
    let relative = parts[3..].join("/");
    let mut members = Vec::new();
    collect_members_naming(&tree, &relative, &mut String::new(), &mut members);
    for (pointer, position) in members {
        // The digest declaration owns the artifact. Repeated script call-site
        // references do not duplicate the same repair diagnostic.
        let Some(parent) = pointer.strip_suffix("/path") else {
            continue;
        };
        if tree
            .pointer(parent)
            .and_then(|node| node.get("digest"))
            .is_some()
        {
            locations.push(PackageMemberLocation {
                artifact: "AdapterPack",
                document: document.clone(),
                pointer,
                position,
            });
        }
    }
    locations
}

fn collect_members_naming(
    node: &Node,
    path: &str,
    pointer: &mut String,
    members: &mut Vec<(String, Position)>,
) {
    let length = pointer.len();
    match &node.value {
        NodeValue::String(text) if text.text == path => {
            members.push((pointer.clone(), node.span.start));
        }
        NodeValue::Mapping(entries) => {
            for entry in entries {
                pointer.push('/');
                pointer.push_str(&escape_pointer_segment(&entry.key));
                collect_members_naming(&entry.value, path, pointer, members);
                pointer.truncate(length);
            }
        }
        NodeValue::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                pointer.push_str(&format!("/{index}"));
                collect_members_naming(item, path, pointer, members);
                pointer.truncate(length);
            }
        }
        _ => {}
    }
}

/// One refusal from loading the verified bundle.
fn push_bundle_error(check: &mut OfflineCheck, layout: &Layout, error: BundleError) {
    let rebuild = "Correct the artifact the message names and rebuild the package with `evidencectl package`.";
    let (code, message) = match error {
        BundleError::Refused(report) => {
            check.extend(*report);
            return;
        }
        BundleError::Package(error) => {
            push_package_error(check, layout, &error);
            return;
        }
        BundleError::Config(fault) => {
            check.push_artifact_fault("evidence.bundle.invalid-configuration", &fault, rebuild);
            return;
        }
        BundleError::InvalidArtifact(fault) => {
            check.push_artifact_fault("evidence.bundle.invalid-artifact", &fault, rebuild);
            return;
        }
        BundleError::InvalidScript(fault) => {
            check.push_artifact_fault("evidence.bundle.invalid-script", &fault, rebuild);
            return;
        }
        BundleError::UnknownFile(fault) => {
            check.push_artifact_fault(
                "evidence.bundle.unknown-file",
                &fault,
                "Remove the file from the project, or reference it from evidence.yaml, and rebuild the package with `evidencectl package`.",
            );
            return;
        }
        BundleError::NotImmutable(fault) => {
            check.push_artifact_fault(
                "evidence.bundle.not-immutable",
                &fault,
                "Make the file read-only for every user, or mount the package read-only.",
            );
            return;
        }
        BundleError::Unavailable => {
            check.mark_unavailable();
            (
                "evidence.bundle.unavailable",
                "a file in the package could not be read",
            )
        }
        BundleError::InvalidPath => (
            "evidence.bundle.invalid-path",
            "the package holds a path a bundle may not carry",
        ),
        BundleError::UnsupportedEntry => (
            "evidence.bundle.unsupported-entry",
            "the package holds an entry that is not a regular file or a directory",
        ),
        BundleError::TooLarge => (
            "evidence.bundle.too-large",
            "the package exceeds a Version 1 size bound",
        ),
    };
    if matches!(
        code,
        "evidence.bundle.unsupported-entry" | "evidence.bundle.too-large"
    ) {
        check.push_package(code, message, REBUILD_PACKAGE_ACTION);
        return;
    }
    check.push_runtime(
        layout,
        code,
        "/package/root",
        false,
        message,
        REBUILD_PACKAGE_ACTION,
    );
}

/// The kind of a package artifact, for the artifacts that are documents with
/// one.
fn artifact_kind(artifact: &str) -> Option<&'static str> {
    if artifact == BUNDLE_DOCUMENT {
        Some(BUNDLE_ARTIFACT)
    } else if artifact.starts_with("codelists/") {
        Some("EvidenceCodelist")
    } else if artifact.starts_with("fixtures/") {
        Some("EvidenceFixture")
    } else {
        None
    }
}

/// The RFC 6901 pointer for a schema path of mapping keys and sequence
/// indices, such as `requirements[0].acquisition`.
fn schema_path_pointer(path: &str) -> String {
    let mut pointer = String::new();
    for segment in path.split('.') {
        let (name, indices) = match segment.find('[') {
            Some(start) => segment.split_at(start),
            None => (segment, ""),
        };
        if !name.is_empty() {
            pointer.push('/');
            pointer.push_str(&escape_pointer_segment(name));
        }
        for index in indices.split(['[', ']']).filter(|index| !index.is_empty()) {
            pointer.push('/');
            pointer.push_str(index);
        }
    }
    pointer
}

fn source(file: &str, position: Option<Position>) -> Source {
    Source {
        file: file.to_owned(),
        line: position.map(|position| position.line),
        column: position.map(|position| position.column),
    }
}

/// Read at most `bound` bytes and one more, so an oversized file is seen as
/// oversized rather than cut to fit.
fn read_bounded(path: &Path, bound: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(bound.saturating_add(1))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The runtime file as the reader saw it, before substitution: where each
/// member was written, and which values a `${...}` expression fills.
struct Layout {
    tree: Option<Node>,
}

impl Layout {
    fn scan(file: &str, bytes: &[u8]) -> Self {
        let mut hook = MarkSubstitutions;
        let tree = Reader::new(file)
            .with_hook(&mut hook)
            .scan(bytes)
            .ok()
            .flatten();
        Self { tree }
    }

    /// Whether the value at `pointer` is filled by substitution.
    fn substituted(&self, pointer: &str) -> bool {
        self.tree
            .as_ref()
            .and_then(|tree| tree.pointer(pointer))
            .is_some_and(|node| matches!(&node.value, NodeValue::String(text) if text.substituted))
    }

    fn locate(&self, pointer: &str, at_key: bool) -> Option<Position> {
        self.tree
            .as_ref()
            .and_then(|tree| locate(tree, pointer, at_key))
    }
}

/// Where a diagnostic about `pointer` points: the member's key or its value
/// when the member is written, and for a member that is not, the key of the
/// nearest mapping that lacks it (CFG-DIAG-1).
fn locate(tree: &Node, pointer: &str, at_key: bool) -> Option<Position> {
    if let Some(node) = tree.pointer(pointer) {
        return if at_key {
            key_position(tree, pointer)
        } else {
            Some(node.span.start)
        };
    }
    let mut ancestor = pointer;
    while let Some((parent, _)) = ancestor.rsplit_once('/') {
        if tree.pointer(parent).is_some() {
            return key_position(tree, parent);
        }
        ancestor = parent;
    }
    Some(tree.span.start)
}

/// The position of the key that names the member at `pointer`, or of the
/// value for a sequence item or the root.
fn key_position(tree: &Node, pointer: &str) -> Option<Position> {
    let Some((parent, last)) = pointer.rsplit_once('/') else {
        return Some(tree.span.start);
    };
    let parent_node = tree.pointer(parent)?;
    let key = last.replace("~1", "/").replace("~0", "~");
    match parent_node.get(&key) {
        Some(entry) => Some(entry.key_span.start),
        None => tree.pointer(pointer).map(|node| node.span.start),
    }
}

/// Marks every value a `${...}` expression would fill, without reading the
/// environment and without refusing anything: the loader already did.
struct MarkSubstitutions;

impl ScalarHook for MarkSubstitutions {
    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        Ok(contains_environment_expression(site.text).then(|| site.text.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acquisition_layout() -> Layout {
        Layout::scan(
            "runtime.yaml",
            b"sourceAcquisition:\n  maximumDataOperations: 2\n",
        )
    }

    #[test]
    fn static_operation_budget_failure_names_the_runtime_limit_and_exact_repair() {
        let mut check = OfflineCheck::new("runtime.yaml".to_owned());
        push_binding_plan_error(
            &mut check,
            &acquisition_layout(),
            RuntimeBindingPlanError::SourcePlan {
                artifact_prefix: "adapter-packs/register/digest".to_owned(),
                error: EvidenceCompileError::StaticOperationBudgetExceeded {
                    required: 3,
                    maximum: 2,
                },
            },
        );

        let [diagnostic] = check.diagnostics.as_slice() else {
            panic!("one runtime budget diagnostic: {:?}", check.diagnostics);
        };
        assert_eq!(
            diagnostic.code,
            "evidence.runtime.source-operation-budget-exceeded"
        );
        assert_eq!(diagnostic.path, "/sourceAcquisition/maximumDataOperations");
        assert_eq!(diagnostic.artifact.as_deref(), Some(RUNTIME_ARTIFACT));
        assert_eq!(
            diagnostic.message,
            "a selected source route requires 3 data operations in its static worst case, above the configured maximum of 2"
        );
        assert_eq!(
            diagnostic.suggested_action,
            "Raise sourceAcquisition.maximumDataOperations to at least 3, or reduce and bound the selected route's sends and retries."
        );
    }

    #[test]
    fn uncountable_static_operation_cost_names_both_repair_causes() {
        let mut check = OfflineCheck::new("runtime.yaml".to_owned());
        push_binding_plan_error(
            &mut check,
            &acquisition_layout(),
            RuntimeBindingPlanError::SourcePlan {
                artifact_prefix: "adapter-packs/register/digest".to_owned(),
                error: EvidenceCompileError::StaticOperationBudgetUncountable,
            },
        );

        let [diagnostic] = check.diagnostics.as_slice() else {
            panic!("one runtime budget diagnostic: {:?}", check.diagnostics);
        };
        assert_eq!(
            diagnostic.code,
            "evidence.runtime.source-operation-budget-uncountable"
        );
        assert_eq!(diagnostic.path, "/sourceAcquisition/maximumDataOperations");
        assert_eq!(diagnostic.artifact.as_deref(), Some(RUNTIME_ARTIFACT));
        assert_eq!(
            diagnostic.message,
            "a selected source route exceeds the reader's nesting or numeric count bound, so its static worst-case data-operation count cannot be derived"
        );
        assert_eq!(
            diagnostic.suggested_action,
            "Reduce the selected route's nesting or bounded operation multipliers, then rebuild the package."
        );
    }

    #[test]
    fn invalid_limits_do_not_add_a_bogus_package_plan_error() {
        let mut check = OfflineCheck::new("runtime.yaml".to_owned());
        push_binding_plan_error(
            &mut check,
            &acquisition_layout(),
            RuntimeBindingPlanError::Limits,
        );
        assert!(
            check.diagnostics.is_empty(),
            "RuntimeConfig::findings owns the invalid-limit diagnostic"
        );
    }

    #[test]
    fn a_schema_path_becomes_a_pointer() {
        assert_eq!(
            schema_path_pointer("requirements[0].acquisition"),
            "/requirements/0/acquisition"
        );
        assert_eq!(schema_path_pointer("a[1][2].b"), "/a/1/2/b");
        assert_eq!(schema_path_pointer("rateLimits"), "/rateLimits");
    }

    #[cfg(unix)]
    #[test]
    fn package_diagnostic_documents_never_follow_a_parent_directory_link() {
        let root = tempfile::tempdir().expect("synthetic package root");
        let outside = tempfile::tempdir().expect("synthetic outside root");
        let digest = "a".repeat(64);
        std::fs::create_dir(outside.path().join(&digest)).unwrap();
        std::fs::write(
            outside.path().join(&digest).join("pack.yaml"),
            b"private synthetic canary",
        )
        .unwrap();
        std::fs::create_dir(root.path().join("adapter-packs")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("adapter-packs/fixture"))
            .unwrap();
        let mut check = OfflineCheck::new("runtime.yaml".to_owned());
        check.package_root = Some(root.path().to_owned());
        assert!(read_package_document(
            &check,
            &format!("adapter-packs/fixture/{digest}/pack.yaml")
        )
        .is_none());
    }
}
