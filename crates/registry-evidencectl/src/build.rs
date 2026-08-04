//! Compile an editable Evidence authoring project into one closed production
//! candidate. Production secrets and target-host paths remain operator-owned.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode},
};

use anyhow::{anyhow, bail, Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::Args;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::{authoring, fixtures, keygen};

const MAX_TARGET_BYTES: u64 = 1024 * 1024;
const SECRET_PREFIX: &str = "secret:file/";
const VALIDATION_CA: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIDMzCCAhugAwIBAgIULquGuNJ2HotUWgpEcRBAdsEtTkUwDQYJKoZIhvcNAQEL
BQAwKTEnMCUGA1UEAwweZXZpZGVuY2VjdGwtdmFsaWRhdGlvbi5pbnZhbGlkMB4X
DTI2MDgwNDE1MjIxMloXDTM2MDgwMTE1MjIxMlowKTEnMCUGA1UEAwweZXZpZGVu
Y2VjdGwtdmFsaWRhdGlvbi5pbnZhbGlkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAqaK57iK2Xspf35AsdY0lCOkUgGRFP7cheDnl855jeW1izSt9ZbBZ
BO9TbUo2J5WnNApOIQFi/57kxX/9HUaTHxaQXsFRgLolYCU5CSWuAI5JMDP0OH+H
xni8AJ1j/cOFovhg/eqRAatF97tBu5Wxh6ghl1eDmZOVeboM/OHns4hauxi6zkdC
oq0ZF7XAQTM7WYbmSewfXcaY5Px4YtyuDJoTVBzsVkp9X3OposyicAXT/5BqPqjC
2jCnM9/PsO9ZpzSZTzeYn06QRtED3hCruCc3isMlWr5lE/KMvMvm9Q+q7+VfariD
qL2UuK4hCRcvTzcbW3s67x3DsohcbuA/OQIDAQABo1MwUTAdBgNVHQ4EFgQUAHgZ
2TkaFqS4edYq+6zlsG6aBDwwHwYDVR0jBBgwFoAUAHgZ2TkaFqS4edYq+6zlsG6a
BDwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAeOvtXp0JMcQw
ouUNvQGlPvu2bcfjsEfvzKOyzjRKmgf4RZYXdFTbV+TkRWjUHjkKjkGE8T18bnBs
3bLuzx0/UJw0b5BxTVSevUgmjnSDqK8XBS8ZyBomcB9MQ+MwPO4ssTDPsZCqOLao
GlhP5e68cbZwmC2YYtgu/bPRSMtlYzTp6wQv2voDlSPZgCUlzfTU67yKsS0dnQaV
wObsZ58XF4WVjuNtyoxtqToUtnrdCP9HUG/I5QiD54IFlVx2dqeWhLa/oyMeAxiR
R1YU60RrYIjPIGEnL+L1WuwoOEu8x09ly2/9wuIWhQPNgVMTCzjwnt8XdVuNecD6
MRmJRtyidQ==
-----END CERTIFICATE-----
"#;

#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Editable Evidence authoring project; defaults to the current directory.
    #[arg(long, default_value = ".")]
    pub project: PathBuf,

    /// Explicit production target containing governance.yaml and runtime.yaml.
    #[arg(long)]
    pub target: PathBuf,

    /// New candidate directory to create. It must not already exist.
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetGovernance {
    version: u32,
    assurance_profile: String,
    service: Value,
    issuer: Value,
    authentication: Value,
    audit: Value,
    subject_binding: Value,
    rate_limits: Value,
    signing: Value,
    #[serde(default)]
    response_formats: Option<Value>,
    authority_profiles: Value,
}

impl TargetGovernance {
    fn into_bundle(self) -> Result<Value> {
        if self.version != 1 {
            bail!("production governance version must be 1");
        }
        if self.assurance_profile != "production" {
            bail!("evidencectl build requires assuranceProfile: production");
        }
        if !self
            .authority_profiles
            .as_object()
            .is_some_and(|profiles| !profiles.is_empty())
        {
            bail!("production governance requires at least one authority profile");
        }
        let mut object = Map::from_iter([
            ("version".to_owned(), json!(self.version)),
            (
                "assuranceProfile".to_owned(),
                Value::String(self.assurance_profile),
            ),
            ("service".to_owned(), self.service),
            ("issuer".to_owned(), self.issuer),
            ("authentication".to_owned(), self.authentication),
            ("audit".to_owned(), self.audit),
            ("subjectBinding".to_owned(), self.subject_binding),
            ("rateLimits".to_owned(), self.rate_limits),
            ("signing".to_owned(), self.signing),
            ("authorityProfiles".to_owned(), self.authority_profiles),
        ]);
        if let Some(response_formats) = self.response_formats {
            object.insert("responseFormats".to_owned(), response_formats);
        }
        Ok(Value::Object(object))
    }
}

pub fn run(args: BuildArgs) -> Result<ExitCode> {
    reject_existing_output(&args.output)?;
    let output_parent = plain_parent(&args.output)?;
    let target = plain_directory(&args.target, "production target")?;
    let governance_bytes = read_plain_file(
        &target.join("governance.yaml"),
        MAX_TARGET_BYTES,
        "production governance",
    )?;
    let target_runtime = read_plain_file(
        &target.join("runtime.yaml"),
        MAX_TARGET_BYTES,
        "production runtime",
    )?;
    let governance: TargetGovernance = serde_norway::from_slice(&governance_bytes)
        .context("production governance is not the closed Version 1 target shape")?;
    let governed_bundle = governance.into_bundle()?;
    let evidence_bin = fixtures::resolve_evidence_binary(None)?;

    let staging = tempfile::Builder::new()
        .prefix(".evidencectl-build-")
        .tempdir_in(&output_parent)
        .with_context(|| format!("staging the candidate in {}", output_parent.display()))?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))
        .context("setting private production candidate staging permissions")?;
    let result = prepare_candidate(
        &args.project,
        staging.path(),
        &target_runtime,
        governed_bundle,
        &evidence_bin,
        &output_parent,
    );
    let (revision, secret_references) = match result {
        Ok(result) => result,
        Err(error) => {
            let _ = make_tree_removable(staging.path());
            return Err(error);
        }
    };
    publish(staging, &args.output)?;

    println!("Bundle revision: {revision}");
    println!("Candidate: {}", args.output.display());
    for reference in secret_references {
        println!("Provision {SECRET_PREFIX}{reference}");
    }
    println!(
        "Target runtime paths and production secret material remain unverified until `evidencectl doctor --project {}` and the target-host Evidence check.",
        args.output.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn prepare_candidate(
    project: &Path,
    staging_root: &Path,
    target_runtime: &[u8],
    governed_bundle: Value,
    evidence_bin: &Path,
    temporary_parent: &Path,
) -> Result<(String, Vec<String>)> {
    let compiled = authoring::compile_production_project(project, staging_root, governed_bundle)?;
    reject_review_markers(&compiled.bundle_path)?;
    reject_review_markers_in_bytes(target_runtime, "production runtime")?;
    let runtime_path = staging_root.join("runtime.yaml");
    write_new_file(&runtime_path, target_runtime, 0o600)?;
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o400))
        .context("sealing the copied production runtime")?;

    let secret_references = secret_references(&compiled.bundle)?;
    let validation = tempfile::Builder::new()
        .prefix(".evidencectl-build-validation-")
        .tempdir_in(temporary_parent)
        .context("creating private production validation state")?;
    fs::set_permissions(validation.path(), fs::Permissions::from_mode(0o700))
        .context("setting private production validation permissions")?;
    let validation_runtime = prepare_validation_runtime(
        validation.path(),
        &compiled.bundle_path,
        &compiled.bundle,
        &secret_references,
    )?;
    let revision = run_check(evidence_bin, &validation_runtime)?;
    for fixture in &compiled.fixture_paths {
        run_fixture(evidence_bin, &validation_runtime, fixture)?;
    }
    Ok((revision, secret_references))
}

fn prepare_validation_runtime(
    root: &Path,
    bundle: &Path,
    config: &Value,
    secret_references: &[String],
) -> Result<PathBuf> {
    let secret_root = root.join("secrets");
    let active_ref = config
        .pointer("/signing/activeKeyRef")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix(SECRET_PREFIX))
        .ok_or_else(|| anyhow!("production signing must use one logical file secret reference"))?;
    let active_key_id = config
        .pointer("/signing/activeKeyId")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("production signing must declare one active key id"))?;
    keygen::generate_dev_keypair(
        &secret_root,
        active_key_id,
        active_ref,
        ".validation-public.jwk.json",
    )?;
    for reference in secret_references {
        if reference == active_ref {
            continue;
        }
        let mut entropy = [0_u8; 32];
        getrandom::fill(&mut entropy).context("generating temporary validation material")?;
        let encoded = URL_SAFE_NO_PAD.encode(entropy);
        write_new_file(&secret_root.join(reference), encoded.as_bytes(), 0o600)?;
    }

    let ca_root = root.join("ca");
    create_private_directory(&ca_root)?;
    let mut trust_profiles = Map::new();
    for profile in tls_trust_profiles(config)? {
        let path = ca_root.join(format!("{profile}.pem"));
        write_new_file(&path, VALIDATION_CA, 0o400)?;
        trust_profiles.insert(profile, json!({"caBundleFile": path.to_string_lossy()}));
    }
    let audit = root.join("audit");
    create_private_directory(&audit)?;
    let runtime = json!({
        "version": 1,
        "bundleDirectory": fs::canonicalize(bundle)?.to_string_lossy(),
        "listener": {
            "bindHost": "127.0.0.1",
            "port": 1,
            "tlsTermination": "operator-controlled-upstream",
            "trustProxyIdentityHeaders": false,
            "maximumRequestBytes": 65536,
            "maximumConcurrentRequests": 1,
            "requestTimeoutMilliseconds": 10000,
            "shutdownGraceMilliseconds": 30000,
        },
        "secretProviders": {"file": {"root": fs::canonicalize(&secret_root)?.to_string_lossy()}},
        "auditStorage": {
            "path": audit.join("evidence.jsonl").to_string_lossy(),
            "maximumFileBytes": 1048576,
        },
        "outboundTls": {"systemRoots": true, "trustProfiles": trust_profiles},
    });
    let path = root.join("runtime.yaml");
    let mut bytes = serde_norway::to_string(&runtime)?.into_bytes();
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    write_new_file(&path, &bytes, 0o400)?;
    Ok(path)
}

fn tls_trust_profiles(config: &Value) -> Result<Vec<String>> {
    let mut profiles = BTreeSet::new();
    if let Some(sources) = config.get("sources").and_then(Value::as_object) {
        for source in sources.values() {
            if let Some(profile) = source.get("tlsTrustProfile").and_then(Value::as_str) {
                if !valid_local_identifier(profile) {
                    bail!("production TLS trust profile identifier is invalid");
                }
                profiles.insert(profile.to_owned());
            }
        }
    }
    Ok(profiles.into_iter().collect())
}

fn run_check(evidence_bin: &Path, runtime: &Path) -> Result<String> {
    let output = Command::new(evidence_bin)
        .arg("--runtime")
        .arg(runtime)
        .arg("check")
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .output()
        .context("running the Evidence production check")?;
    if !output.status.success() {
        return runtime_failure("Evidence rejected the generated production bundle");
    }
    parse_bundle_revision(&String::from_utf8_lossy(&output.stdout))
}

fn run_fixture(evidence_bin: &Path, runtime: &Path, fixture: &str) -> Result<()> {
    let output = Command::new(evidence_bin)
        .arg("--runtime")
        .arg(runtime)
        .arg("evaluate")
        .arg("--fixture")
        .arg(fixture)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .output()
        .context("running one Evidence production fixture")?;
    if output.status.success() {
        return Ok(());
    }
    runtime_failure("Evidence rejected a production fixture")
}

fn runtime_failure<T>(message: &str) -> Result<T> {
    // Evidence diagnostics are intentionally not relayed here. A validation
    // process may have opened operator-authored configuration, and build
    // failures must remain value-free even if that subprocess is replaced.
    bail!("{message}")
}

fn parse_bundle_revision(stdout: &str) -> Result<String> {
    let revision = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Evidence deployment "))
        .and_then(|line| line.split_whitespace().next())
        .filter(|value| {
            value.len() == 71
                && value.starts_with("sha256:")
                && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or_else(|| anyhow!("Evidence check returned no bundle revision"))?;
    Ok(revision.to_owned())
}

fn secret_references(value: &Value) -> Result<Vec<String>> {
    let mut references = BTreeSet::new();
    collect_secret_references(value, &mut references)?;
    Ok(references.into_iter().collect())
}

fn collect_secret_references(value: &Value, references: &mut BTreeSet<String>) -> Result<()> {
    match value {
        Value::String(value) => {
            if let Some(reference) = value.strip_prefix(SECRET_PREFIX) {
                if !valid_secret_name(reference) {
                    bail!("production logical file secret reference has invalid syntax");
                }
                references.insert(reference.to_owned());
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_secret_references(value, references)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_secret_references(value, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn valid_secret_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 128
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_local_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 128
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn reject_review_markers(bundle: &Path) -> Result<()> {
    for path in bundle_files(bundle)? {
        let bytes = fs::read(&path).context("reading one generated bundle artifact")?;
        reject_review_markers_in_bytes(&bytes, "production bundle")?;
    }
    Ok(())
}

fn reject_review_markers_in_bytes(bytes: &[u8], description: &str) -> Result<()> {
    if [
        b"TODO(evidencectl)".as_slice(),
        b"review-required",
        b"placeholder_fact",
    ]
    .iter()
    .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
    {
        bail!("the {description} contains an unresolved authoring review marker");
    }
    Ok(())
}

fn bundle_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path).context("walking the generated bundle")? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!("the generated bundle contains a symbolic link");
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                files.push(path);
            } else {
                bail!("the generated bundle contains an unsupported entry");
            }
        }
    }
    files.sort();
    Ok(files)
}

fn reject_existing_output(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("output already exists; evidencectl build never overwrites a candidate"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspecting the candidate output path"),
    }
}

fn plain_parent(path: &Path) -> Result<PathBuf> {
    if !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        bail!("candidate output must name one new directory");
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    validate_plain_components(parent, "candidate parent", true)?;
    fs::canonicalize(parent).context("resolving the candidate parent")
}

fn plain_directory(path: &Path, description: &str) -> Result<PathBuf> {
    validate_plain_components(path, description, true)?;
    fs::canonicalize(path).with_context(|| format!("resolving {description} directory"))
}

fn validate_plain_components(
    path: &Path,
    description: &str,
    final_is_directory: bool,
) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let components = absolute.components().collect::<Vec<_>>();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(value) => current.push(value),
            Component::CurDir => continue,
            Component::ParentDir | Component::Prefix(_) => {
                bail!("{description} must not contain path traversal")
            }
        }
        let metadata =
            fs::symlink_metadata(&current).with_context(|| format!("inspecting {description}"))?;
        if metadata.file_type().is_symlink() {
            bail!("{description} must not traverse symbolic links");
        }
        let is_final = index + 1 == components.len();
        if (!is_final || final_is_directory) && !metadata.is_dir() {
            bail!("{description} must be an existing plain directory");
        }
    }
    Ok(())
}

fn read_plain_file(path: &Path, maximum: u64, description: &str) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags};
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("opening {description}"))?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum {
        bail!("{description} must be a bounded regular file");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("{description} exceeds its byte limit");
    }
    Ok(bytes)
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("creating {}", path.display()))
}

fn write_new_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn make_tree_removable(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("private staging contains a symbolic link");
        }
        if metadata.is_dir() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            make_tree_removable(&path)?;
        } else if metadata.is_file() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        } else {
            bail!("private staging contains an unsupported entry");
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn publish(staging: tempfile::TempDir, output: &Path) -> Result<()> {
    let staged = staging.keep();
    if let Err(error) = rename_noreplace(&staged, output) {
        let _ = make_tree_removable(&staged);
        let _ = fs::remove_dir_all(&staged);
        return Err(error).context("publishing the production candidate without replacement");
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
        "atomic no-replace candidate publication is unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn production_governance_is_closed_at_the_target_boundary() {
        let unknown = serde_norway::from_str::<TargetGovernance>(
            r#"version: 1
assuranceProfile: production
service: {}
issuer: {}
authentication: {}
audit: {}
subjectBinding: {}
rateLimits: {}
signing: {}
authorityProfiles: {}
requirements: []
"#,
        );
        assert!(unknown.is_err());
    }

    #[test]
    fn revision_and_secret_reference_parsing_are_closed() {
        let revision = format!("Evidence deployment sha256:{}\n", "a".repeat(64));
        assert_eq!(
            parse_bundle_revision(&revision).expect("revision"),
            format!("sha256:{}", "a".repeat(64))
        );
        assert!(parse_bundle_revision("Evidence deployment sha256:not-a-digest\n").is_err());

        let names = secret_references(&json!({
            "z": "secret:file/source-token",
            "a": ["secret:file/audit-key", "secret:file/source-token"]
        }))
        .expect("references");
        assert_eq!(names, ["audit-key", "source-token"]);
        assert!(secret_references(&json!({"key": "secret:file/../escape"})).is_err());
        assert!(secret_references(&json!({"key": "secret:file/nested/escape"})).is_err());
        assert!(tls_trust_profiles(&json!({
            "sources": {"source": {"tlsTrustProfile": "../../escape"}}
        }))
        .is_err());
    }

    #[test]
    fn target_and_candidate_paths_reject_ancestor_symlinks() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = fs::canonicalize(temporary.path()).expect("canonical tempdir");
        let actual = root.join("actual");
        fs::create_dir(&actual).expect("actual directory");
        let link = root.join("link");
        symlink(&actual, &link).expect("ancestor symlink");

        assert!(plain_directory(&link, "production target").is_err());
        assert!(plain_parent(&link.join("candidate")).is_err());
    }

    #[test]
    fn review_markers_are_rejected_without_repeating_authored_values() {
        for marker in ["TODO(evidencectl)", "review-required", "placeholder_fact"] {
            let error = reject_review_markers_in_bytes(marker.as_bytes(), "production runtime")
                .expect_err("review marker rejected")
                .to_string();
            assert!(!error.contains(marker));
        }
    }
}
