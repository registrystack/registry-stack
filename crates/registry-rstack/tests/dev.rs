use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn scratch() -> tempfile::TempDir {
    if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
        tempfile::tempdir_in(target).unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}

fn executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("macos", "aarch64") => "macos-arm64",
        other => panic!("unsupported test platform: {other:?}"),
    }
}

fn release_asset(directory: &Path, binary: &str, body: &str, fips: bool) -> (String, Vec<u8>) {
    let release = format!("v{CURRENT_VERSION}");
    let platform = platform();
    let archived = platform == "macos-arm64";
    let asset_name = format!(
        "{binary}-{release}-{platform}{}",
        if archived { ".tar.gz" } else { "" }
    );
    let asset = directory.join(&asset_name);
    if archived {
        let contents = directory.join(format!("contents-{binary}"));
        fs::create_dir(&contents).unwrap();
        let archived_binary = asset_name.trim_end_matches(".tar.gz");
        executable(&contents.join(archived_binary), body);
        fs::write(contents.join("THIRD_PARTY_NOTICES"), "fixture\n").unwrap();
        let mut entries = vec![archived_binary, "THIRD_PARTY_NOTICES"];
        if fips {
            fs::write(contents.join("libaws_lc_fips_test.dylib"), "fixture\n").unwrap();
            entries.push("libaws_lc_fips_test.dylib");
        }
        let output = Command::new("tar")
            .arg("-czf")
            .arg(&asset)
            .arg("-C")
            .arg(&contents)
            .args(entries)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    } else {
        executable(&asset, body);
    }
    let bytes = fs::read(asset).unwrap();
    (asset_name, bytes)
}

fn versioned_tool(binary: &str, body: &str) -> String {
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nif [[ \"${{1:-}}\" == '--version' ]]; then printf '{binary} {CURRENT_VERSION}\\n'; exit 0; fi\n{body}"
    )
}

/// A stand-in for a product CLI that hosts the development runner: it reports
/// its name, its arguments, and the environment the launcher passed it.
fn host_body(name: &str) -> String {
    format!(
        "printf 'host:{name}\\n'\nprintf 'arg:%s\\n' \"$@\"\nif [[ -n \"${{EXPECTED_DATABASE_URL:-}}\" ]]; then\n  [[ \"${{RSTACK_DEV_DATABASE_URL:-}}\" == \"$EXPECTED_DATABASE_URL\" ]]\n  printf 'database:matched\\n'\nelse\n  printf 'database:%s\\n' \"${{RSTACK_DEV_DATABASE_URL:+set}}\"\nfi\nprintf 'generation:%s\\n' \"${{RSTACK_GENERATION_DIR:-}}\"\nprintf 'release:%s\\n' \"${{RSTACK_RELEASE_TAG:-}}\"\nprintf 'bregctl:%s\\n' \"${{RSTACK_BREGCTL_BIN:-}}\"\nprintf 'breg:%s\\n' \"${{RSTACK_BREG_BIN:-}}\"\nprintf 'caseworkctl:%s\\n' \"${{RSTACK_CASEWORKCTL_BIN:-}}\"\nprintf 'casework:%s\\n' \"${{RSTACK_CASEWORK_BIN:-}}\"\nprintf 'evidencectl:%s\\n' \"${{RSTACK_EVIDENCECTL_BIN:-}}\"\nprintf 'evidence:%s\\n' \"${{RSTACK_EVIDENCE_BIN:-}}\"\nprintf 'messagingctl:%s\\n' \"${{RSTACK_MESSAGINGCTL_BIN:-}}\"\nprintf 'messaging:%s\\n' \"${{RSTACK_MESSAGING_BIN:-}}\"\n"
    )
}

struct ManagedInstall {
    _scratch: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    project: PathBuf,
}

fn managed_install() -> ManagedInstall {
    let scratch = scratch();
    let assets = scratch.path().join("assets");
    fs::create_dir(&assets).unwrap();
    let executable = env!("CARGO_BIN_EXE_rstack").replace('\'', "'\"'\"'");
    let launcher_body = format!(
        "#!/usr/bin/env bash\nset -euo pipefail\nif [[ \"${{1:-}}\" == '--version' ]]; then printf 'rstack {CURRENT_VERSION}\\n'; exit 0; fi\nif [[ -n \"${{REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}}\" ]]; then export DYLD_FALLBACK_LIBRARY_PATH=\"$REGISTRY_CARGO_RUNTIME_LIBRARY_PATH\"; fi\nexec '{executable}' \"$@\"\n"
    );
    let (launcher_name, launcher_bytes) = release_asset(&assets, "rstack", &launcher_body, false);
    let (bregctl_name, bregctl_bytes) = release_asset(
        &assets,
        "bregctl",
        &versioned_tool("bregctl", &host_body("bregctl")),
        true,
    );
    let (breg_name, breg_bytes) =
        release_asset(&assets, "breg", &versioned_tool("breg", "exit 0\n"), true);
    let (caseworkctl_name, caseworkctl_bytes) = release_asset(
        &assets,
        "caseworkctl",
        &versioned_tool("caseworkctl", &host_body("caseworkctl")),
        true,
    );
    let (casework_name, casework_bytes) = release_asset(
        &assets,
        "casework",
        &versioned_tool("casework", "exit 0\n"),
        true,
    );
    let release = format!("v{CURRENT_VERSION}");
    let platform = platform();
    let payload = |name: &str, bytes: &[u8]| {
        serde_json::json!({
            "name":name,
            "kind":"binary",
            "size":bytes.len(),
            "sha256":digest(bytes)
        })
    };
    let component_asset = |name: &str, bytes: &[u8]| serde_json::json!({"name":name,"size":bytes.len(),"sha256":digest(bytes)});
    let manifest_name = format!("registry-stack-{release}-release-manifest.json");
    let manifest_path = assets.join(&manifest_name);
    let manifest = serde_json::json!({
        "schema_version":"registry-stack.release-candidate.v2",
        "repository":"registrystack/registry-stack",
        "release":{"tag":release.as_str(),"version":CURRENT_VERSION,"source_sha":"a".repeat(40),"release_id":"test"},
        "payloads":[
            payload(&launcher_name, &launcher_bytes),
            payload(&bregctl_name, &bregctl_bytes),
            payload(&breg_name, &breg_bytes),
            payload(&caseworkctl_name, &caseworkctl_bytes),
            payload(&casework_name, &casework_bytes)
        ],
        "components":{
            "schema_version":"registry-stack.components.v1",
            "release":release.as_str(),
            "launcher":{(platform):component_asset(&launcher_name, &launcher_bytes)},
            "components":{
                "breg":{
                    "entrypoint":"bregctl",
                    "dependencies":[],
                    "platforms":{(platform):{
                        "assets":[
                            component_asset(&bregctl_name, &bregctl_bytes),
                            component_asset(&breg_name, &breg_bytes)
                        ],
                        "capabilities":{"tooling":true,"runtime":true}
                    }}
                },
                "casework":{
                    "entrypoint":"caseworkctl",
                    "dependencies":["breg"],
                    "platforms":{(platform):{
                        "assets":[
                            component_asset(&caseworkctl_name, &caseworkctl_bytes),
                            component_asset(&casework_name, &casework_bytes)
                        ],
                        "capabilities":{"tooling":true,"runtime":true}
                    }}
                }
            }
        }
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    fs::write(&manifest_path, &manifest_bytes).unwrap();
    let checksums = assets.join("SHA256SUMS");
    let mut checksum_text = String::new();
    for (name, bytes) in [
        (&launcher_name, &launcher_bytes),
        (&bregctl_name, &bregctl_bytes),
        (&breg_name, &breg_bytes),
        (&caseworkctl_name, &caseworkctl_bytes),
        (&casework_name, &casework_bytes),
    ] {
        checksum_text.push_str(&format!("{}  {name}\n", digest(bytes)));
    }
    checksum_text.push_str(&format!("{}  {manifest_name}\n", digest(&manifest_bytes)));
    fs::write(&checksums, checksum_text).unwrap();

    let root = scratch.path().join("lib");
    let bin = scratch.path().join("bin");
    let installed = Command::new(env!("CARGO_BIN_EXE_rstack"))
        .args(["bootstrap", "--release-manifest"])
        .arg(&manifest_path)
        .arg("--checksum-file")
        .arg(&checksums)
        .arg("--launcher-asset")
        .arg(assets.join(&launcher_name))
        .arg("--asset-dir")
        .arg(&assets)
        .arg("--install-root")
        .arg(&root)
        .arg("--bin-dir")
        .arg(&bin)
        .args(["breg", "casework"])
        .output()
        .unwrap();
    assert!(installed.status.success(), "{installed:?}");
    let project = scratch.path().join("project");
    fs::create_dir(&project).unwrap();
    ManagedInstall {
        _scratch: scratch,
        root,
        bin,
        project,
    }
}

struct SourceTools {
    _scratch: tempfile::TempDir,
    project: PathBuf,
    install_root: PathBuf,
    bin_dir: PathBuf,
    bregctl: PathBuf,
    breg: PathBuf,
    caseworkctl: PathBuf,
    casework: PathBuf,
    evidencectl: PathBuf,
    evidence: PathBuf,
    messagingctl: PathBuf,
    messaging: PathBuf,
}

impl SourceTools {
    fn new() -> Self {
        let scratch = scratch();
        let project = scratch.path().join("registry project");
        fs::create_dir(&project).unwrap();
        let install_root = scratch.path().join("uninstalled");
        let bin_dir = scratch.path().join("bin");
        let bregctl = scratch.path().join("bregctl");
        let caseworkctl = scratch.path().join("caseworkctl");
        let evidencectl = scratch.path().join("evidencectl");
        let messagingctl = scratch.path().join("messagingctl");
        for (path, name) in [
            (&bregctl, "bregctl"),
            (&caseworkctl, "caseworkctl"),
            (&evidencectl, "evidencectl"),
            (&messagingctl, "messagingctl"),
        ] {
            executable(
                path,
                &format!(
                    "#!/usr/bin/env bash\nset -euo pipefail\n{}",
                    host_body(name)
                ),
            );
        }
        let breg = scratch.path().join("breg");
        let casework = scratch.path().join("casework");
        let evidence = scratch.path().join("evidence");
        let messaging = scratch.path().join("messaging");
        for path in [&breg, &casework, &evidence, &messaging] {
            executable(path, "#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n");
        }
        Self {
            _scratch: scratch,
            project,
            install_root,
            bin_dir,
            bregctl,
            breg,
            caseworkctl,
            casework,
            evidencectl,
            evidence,
            messagingctl,
            messaging,
        }
    }

    fn empty_command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rstack"));
        command
            .args(["--install-root", self.install_root.to_str().unwrap()])
            .args(["--bin-dir", self.bin_dir.to_str().unwrap()])
            .env_remove("RSTACK_DEV_DATABASE_URL")
            .env_remove("RSTACK_BREGCTL_BIN")
            .env_remove("RSTACK_BREG_BIN")
            .env_remove("RSTACK_CASEWORKCTL_BIN")
            .env_remove("RSTACK_CASEWORK_BIN")
            .env_remove("RSTACK_EVIDENCECTL_BIN")
            .env_remove("RSTACK_EVIDENCE_BIN")
            .env_remove("RSTACK_MESSAGINGCTL_BIN")
            .env_remove("RSTACK_MESSAGING_BIN");
        command
    }

    fn command(&self) -> Command {
        let mut command = self.empty_command();
        command
            .env("RSTACK_BREGCTL_BIN", &self.bregctl)
            .env("RSTACK_BREG_BIN", &self.breg)
            .env("RSTACK_CASEWORKCTL_BIN", &self.caseworkctl)
            .env("RSTACK_CASEWORK_BIN", &self.casework)
            .env("RSTACK_EVIDENCECTL_BIN", &self.evidencectl)
            .env("RSTACK_EVIDENCE_BIN", &self.evidence)
            .env("RSTACK_MESSAGINGCTL_BIN", &self.messagingctl)
            .env("RSTACK_MESSAGING_BIN", &self.messaging);
        command
    }
}

fn output_field<'a>(output: &'a str, name: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}:")))
        .unwrap_or_else(|| panic!("missing {name} in {output}"))
}

/// The host CLI the launcher ran, and the arguments it passed that host.
fn hosted(output: &Output) -> (String, Vec<String>) {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let host = output_field(&stdout, "host").to_owned();
    let arguments = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("arg:"))
        .map(str::to_owned)
        .collect();
    (host, arguments)
}

/// The arguments a host receives: the hidden runner subcommand, the action,
/// its options, and the project or run ID after `--`.
fn runner_arguments(action: &str, options: &[&str], target: &Path) -> Vec<String> {
    ["rstack-dev", action]
        .into_iter()
        .chain(options.iter().copied())
        .map(str::to_owned)
        .chain(["--".to_owned(), target.to_str().unwrap().to_owned()])
        .collect()
}

#[test]
fn managed_start_uses_one_release_generation_on_supported_platforms() {
    let install = managed_install();
    write_plan(&install.project, &["casework", "breg"]);
    let database_url = "postgresql://example.invalid/managed-secret";
    let output = Command::new(install.bin.join("rstack"))
        .arg("--install-root")
        .arg(&install.root)
        .arg("--bin-dir")
        .arg(&install.bin)
        .args(["dev", "start"])
        .arg(&install.project)
        .args(["--database-url", database_url])
        .env("EXPECTED_DATABASE_URL", database_url)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(!stdout.contains(database_url), "{stdout}");
    assert!(stdout.contains("database:matched\n"), "{stdout}");
    // BReg comes first in the hosting order, whatever order the plan lists.
    assert_eq!(
        hosted(&output),
        (
            "bregctl".to_owned(),
            runner_arguments("start", &[], &install.project)
        )
    );
    let generation = PathBuf::from(output_field(&stdout, "generation"));
    assert_eq!(
        output_field(&stdout, "release"),
        format!("v{CURRENT_VERSION}")
    );
    for (name, relative) in [
        ("bregctl", "components/breg/bregctl/bregctl"),
        ("breg", "components/breg/breg/breg"),
        ("caseworkctl", "components/casework/caseworkctl/caseworkctl"),
        ("casework", "components/casework/casework/casework"),
    ] {
        assert_eq!(
            PathBuf::from(output_field(&stdout, name)),
            generation.join(relative)
        );
    }
}

#[test]
fn source_start_passes_one_argument_list_and_binary_set() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["breg", "casework"]);
    let database_url = "postgresql://example.invalid/dev-secret";
    let output = tools
        .command()
        .args(["dev", "start"])
        .arg(&tools.project)
        .args(["--ttl", "45m", "--database-url", database_url])
        .env("EXPECTED_DATABASE_URL", database_url)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert_eq!(
        hosted(&output),
        (
            "bregctl".to_owned(),
            runner_arguments("start", &["--ttl=45m"], &tools.project)
        )
    );
    assert!(stdout.contains("database:matched\n"));
    assert!(stdout.contains(&format!("bregctl:{}\n", tools.bregctl.display())));
    assert!(stdout.contains(&format!("breg:{}\n", tools.breg.display())));
    assert!(stdout.contains(&format!("caseworkctl:{}\n", tools.caseworkctl.display())));
    assert!(stdout.contains(&format!("casework:{}\n", tools.casework.display())));
    assert!(!stdout.contains(database_url));
}

#[test]
fn source_start_passes_a_built_application_root_to_the_runner() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["breg"]);
    let database_url = "postgresql://example.invalid/dev-secret";
    let application_root = tools.project.join("built-application");
    let output = tools
        .command()
        .args(["dev", "start"])
        .arg(&tools.project)
        .arg("--application-root")
        .arg(&application_root)
        .args(["--database-url", database_url])
        .env("EXPECTED_DATABASE_URL", database_url)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        hosted(&output).1,
        runner_arguments(
            "start",
            &[&format!(
                "--application-root={}",
                application_root.to_str().unwrap()
            )],
            &tools.project
        )
    );
}

#[test]
fn dev_actions_encode_the_public_contract_and_launcher_json_format() {
    let tools = SourceTools::new();
    let run = |id: &str| PathBuf::from(id);
    for (arguments, expected) in [
        (
            vec![
                "dev",
                "check",
                tools.project.to_str().unwrap(),
                "--deny-warnings",
            ],
            runner_arguments("check", &["--deny-warnings"], &tools.project),
        ),
        (
            vec!["--format", "json", "dev", "status", "run-1"],
            runner_arguments("status", &["--json"], &run("run-1")),
        ),
        (
            vec![
                "--format", "json", "dev", "token", "run-2", "--as", "reviewer",
            ],
            runner_arguments("token", &["--as=reviewer", "--json"], &run("run-2")),
        ),
        (
            vec!["dev", "stop", "run-3"],
            runner_arguments("stop", &[], &run("run-3")),
        ),
        (
            vec!["--format", "json", "dev", "stop", "run-4"],
            runner_arguments("stop", &["--json"], &run("run-4")),
        ),
        (
            vec!["--format", "json", "dev", "stop", "run-5", "--recover"],
            runner_arguments("stop", &["--recover", "--json"], &run("run-5")),
        ),
        (
            vec!["dev", "status", "--", "-run-6"],
            runner_arguments("status", &[], &run("-run-6")),
        ),
    ] {
        let output = tools
            .empty_command()
            .args(&arguments)
            .env("RSTACK_BREGCTL_BIN", &tools.bregctl)
            .output()
            .unwrap();
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        assert_eq!(hosted(&output), ("bregctl".to_owned(), expected));
    }
}

#[test]
fn recover_passes_the_administrator_url_through_the_environment_only() {
    let tools = SourceTools::new();
    let database_url = "postgresql://example.invalid/dev-secret";
    let output = tools
        .empty_command()
        .args([
            "dev",
            "stop",
            "run-6",
            "--recover",
            "--database-url",
            database_url,
        ])
        .env("RSTACK_BREGCTL_BIN", &tools.bregctl)
        .env("EXPECTED_DATABASE_URL", database_url)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(stdout.contains("database:matched\n"), "{stdout}");
    assert!(!stdout.contains(database_url));
    assert_eq!(
        hosted(&output).1,
        runner_arguments("stop", &["--recover"], Path::new("run-6"))
    );
}

#[test]
fn database_url_is_refused_for_stop_without_recover() {
    let tools = SourceTools::new();
    let output = tools
        .empty_command()
        .args([
            "dev",
            "stop",
            "run-7",
            "--database-url",
            "postgresql://example.invalid/x",
        ])
        .env("RSTACK_BREGCTL_BIN", &tools.bregctl)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[test]
fn start_requires_the_complete_source_binary_set_without_an_installation() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["breg", "casework"]);
    let output = tools
        .empty_command()
        .args(["dev", "start"])
        .arg(&tools.project)
        .env("RSTACK_BREGCTL_BIN", &tools.bregctl)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("RSTACK_BREG_BIN"), "{stderr}");
    assert!(stderr.contains("RSTACK_CASEWORKCTL_BIN"), "{stderr}");
    assert!(stderr.contains("RSTACK_CASEWORK_BIN"), "{stderr}");
}

#[test]
fn root_and_dev_help_need_no_installation_or_binary_overrides() {
    let tools = SourceTools::new();
    for (arguments, expected) in [
        (&["--help"][..], &["dev"][..]),
        (
            &["dev", "--help"][..],
            &["check", "start", "status", "token", "stop"][..],
        ),
        (
            &["dev", "check", "--help"][..],
            &[
                "PROJECT",
                "--deny-warnings",
                "rstack dev check ./my-registry-project",
            ][..],
        ),
        (
            &["dev", "start", "--help"][..],
            &[
                "--database-url",
                "--ttl",
                "rstack dev start ./my-registry-project",
            ][..],
        ),
        (
            &["dev", "stop", "--help"][..],
            &[
                "--recover",
                "--database-url",
                "rstack dev stop 0123456789abcdef0123456789abcdef",
            ][..],
        ),
    ] {
        let output = tools.empty_command().args(arguments).output().unwrap();
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        assert!(output.stderr.is_empty(), "{arguments:?}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        for text in expected {
            assert!(stdout.contains(text), "{arguments:?}: {stdout}");
        }
    }
}

fn write_plan(project: &Path, products: &[&str]) {
    let entries: Vec<String> = products
        .iter()
        .map(|product| {
            format!("  - {{product: {product}, project: {product}, audience: \"urn:example:{product}\"}}\n")
        })
        .collect();
    fs::write(
        project.join("dev.yaml"),
        format!(
            "issuer: https://issuer.example\nproducts:\n{}",
            entries.concat()
        ),
    )
    .unwrap();
}

/// Validates a launcher failure against the documented error schema.
fn assert_matches_error_schema(report: &Value) {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../products/platform/schemas/rstack-dev-error.v1.schema.json"
    ))
    .unwrap();
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    if let Err(errors) = schema.validate(report) {
        let errors: Vec<_> = errors.map(|error| error.to_string()).collect();
        panic!("{report} violates the error schema: {errors:?}");
    };
}

#[test]
fn format_json_makes_dev_failures_json() {
    let tools = SourceTools::new();
    let output = tools
        .empty_command()
        .args(["--format", "json", "dev", "start", "/missing"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "registry.rstack.error.v1");
    assert_eq!(report["status"], "refused");
    assert_eq!(report["error"]["class"], "domain");
    assert_matches_error_schema(&report);

    let usage = tools
        .empty_command()
        .args(["--format", "json", "dev", "token", "run-1"])
        .output()
        .unwrap();
    assert_eq!(usage.status.code(), Some(2), "{usage:?}");
    let report: Value = serde_json::from_slice(&usage.stdout).unwrap();
    assert_eq!(report["schema_version"], "registry.rstack.error.v1");
    assert_eq!(report["error"]["class"], "usage");
    assert_matches_error_schema(&report);

    let human = tools
        .empty_command()
        .args(["dev", "start", "/missing"])
        .output()
        .unwrap();
    assert_eq!(human.status.code(), Some(1), "{human:?}");
    assert!(human.stdout.is_empty(), "{human:?}");
    assert!(String::from_utf8(human.stderr)
        .unwrap()
        .starts_with("rstack: "));
}

#[test]
fn dev_json_flag_is_refused() {
    let tools = SourceTools::new();
    for arguments in [
        &["dev", "check", "/p", "--json"][..],
        &["dev", "start", "/p", "--json"][..],
        &["dev", "status", "run-1", "--json"][..],
        &["dev", "token", "run-1", "--as", "x", "--json"][..],
        &["dev", "stop", "run-1", "--json"][..],
    ] {
        let output = tools.empty_command().args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("--json"), "{arguments:?}: {stderr}");
    }
}

#[test]
fn help_dev_is_accepted() {
    let tools = SourceTools::new();
    let output = tools
        .empty_command()
        .args(["help", "dev"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    for text in ["check", "start", "status", "token", "stop"] {
        assert!(stdout.contains(text), "{stdout}");
    }
    assert!(!stdout.contains("--install-root"), "{stdout}");
}

#[test]
fn dev_help_hides_the_installer_path_flags() {
    let tools = SourceTools::new();
    for arguments in [
        &["dev", "--help"][..],
        &["dev", "start", "--help"][..],
        &["dev", "stop", "--help"][..],
    ] {
        let output = tools.empty_command().args(arguments).output().unwrap();
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        for flag in ["--install-root", "--bin-dir", "--asset-dir"] {
            assert!(!stdout.contains(flag), "{arguments:?}: {stdout}");
        }
    }
}

#[test]
fn breg_only_plan_does_not_require_casework_binaries() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["breg"]);
    let output = tools
        .empty_command()
        .args(["dev", "start"])
        .arg(&tools.project)
        .env("RSTACK_BREGCTL_BIN", &tools.bregctl)
        .env("RSTACK_BREG_BIN", &tools.breg)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(hosted(&output).0, "bregctl");
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert_eq!(output_field(&stdout, "caseworkctl"), "");
    assert_eq!(output_field(&stdout, "casework"), "");
}

#[test]
fn casework_only_plan_needs_no_breg_binaries() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["casework"]);
    let missing = tools._scratch.path().join("not-installed");
    let launch = |arguments: &[&str]| {
        tools
            .empty_command()
            .args(arguments)
            .arg(&tools.project)
            .env("RSTACK_BREGCTL_BIN", missing.join("bregctl"))
            .env("RSTACK_BREG_BIN", missing.join("breg"))
            .env("RSTACK_CASEWORKCTL_BIN", &tools.caseworkctl)
            .env("RSTACK_CASEWORK_BIN", &tools.casework)
            .output()
            .unwrap()
    };

    let checked = launch(&["dev", "check"]);
    assert!(checked.status.success(), "{checked:?}");
    assert_eq!(
        hosted(&checked),
        (
            "caseworkctl".to_owned(),
            runner_arguments("check", &[], &tools.project)
        )
    );

    let started = launch(&["dev", "start"]);
    assert!(started.status.success(), "{started:?}");
    assert_eq!(
        hosted(&started),
        (
            "caseworkctl".to_owned(),
            runner_arguments("start", &[], &tools.project)
        )
    );
}

#[test]
fn casework_only_check_names_the_casework_install_and_override() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["casework"]);
    let output = tools
        .empty_command()
        .args(["dev", "check"])
        .arg(&tools.project)
        .env("RSTACK_BREGCTL_BIN", &tools.bregctl)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("rstack install casework"), "{stderr}");
    assert!(stderr.contains("RSTACK_CASEWORKCTL_BIN"), "{stderr}");
    assert!(!stderr.contains("RSTACK_BREGCTL_BIN"), "{stderr}");
    assert!(!stderr.contains("RSTACK_CASEWORK_BIN"), "{stderr}");
}

#[test]
fn evidence_only_plan_needs_only_evidence_binaries() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["evidence"]);
    let missing = tools._scratch.path().join("not-installed");
    let launch = |arguments: &[&str]| {
        tools
            .empty_command()
            .args(arguments)
            .arg(&tools.project)
            .env("RSTACK_BREGCTL_BIN", missing.join("bregctl"))
            .env("RSTACK_BREG_BIN", missing.join("breg"))
            .env("RSTACK_CASEWORKCTL_BIN", missing.join("caseworkctl"))
            .env("RSTACK_CASEWORK_BIN", missing.join("casework"))
            .env("RSTACK_EVIDENCECTL_BIN", &tools.evidencectl)
            .env("RSTACK_EVIDENCE_BIN", &tools.evidence)
            .output()
            .unwrap()
    };

    let checked = launch(&["dev", "check"]);
    assert!(checked.status.success(), "{checked:?}");
    assert_eq!(
        hosted(&checked),
        (
            "evidencectl".to_owned(),
            runner_arguments("check", &[], &tools.project)
        )
    );

    let started = launch(&["dev", "start"]);
    assert!(started.status.success(), "{started:?}");
    assert_eq!(
        hosted(&started),
        (
            "evidencectl".to_owned(),
            runner_arguments("start", &[], &tools.project)
        )
    );
    let stdout = String::from_utf8(started.stdout.clone()).unwrap();
    assert_eq!(
        output_field(&stdout, "evidencectl"),
        tools.evidencectl.display().to_string()
    );
    assert_eq!(
        output_field(&stdout, "evidence"),
        tools.evidence.display().to_string()
    );
}

#[test]
fn messaging_only_plan_needs_only_messaging_binaries() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["messaging"]);
    let missing = tools._scratch.path().join("not-installed");
    let launch = |arguments: &[&str]| {
        tools
            .empty_command()
            .args(arguments)
            .arg(&tools.project)
            .env("RSTACK_BREGCTL_BIN", missing.join("bregctl"))
            .env("RSTACK_BREG_BIN", missing.join("breg"))
            .env("RSTACK_CASEWORKCTL_BIN", missing.join("caseworkctl"))
            .env("RSTACK_CASEWORK_BIN", missing.join("casework"))
            .env("RSTACK_EVIDENCECTL_BIN", missing.join("evidencectl"))
            .env("RSTACK_EVIDENCE_BIN", missing.join("evidence"))
            .env("RSTACK_MESSAGINGCTL_BIN", &tools.messagingctl)
            .env("RSTACK_MESSAGING_BIN", &tools.messaging)
            .output()
            .unwrap()
    };

    let checked = launch(&["dev", "check"]);
    assert!(checked.status.success(), "{checked:?}");
    assert_eq!(
        hosted(&checked),
        (
            "messagingctl".to_owned(),
            runner_arguments("check", &[], &tools.project)
        )
    );

    let started = launch(&["dev", "start"]);
    assert!(started.status.success(), "{started:?}");
    assert_eq!(
        hosted(&started),
        (
            "messagingctl".to_owned(),
            runner_arguments("start", &[], &tools.project)
        )
    );
    let stdout = String::from_utf8(started.stdout.clone()).unwrap();
    assert_eq!(
        output_field(&stdout, "messagingctl"),
        tools.messagingctl.display().to_string()
    );
    assert_eq!(
        output_field(&stdout, "messaging"),
        tools.messaging.display().to_string()
    );
}

#[test]
fn messaging_only_check_names_the_messaging_install_and_override() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["messaging"]);
    let output = tools
        .empty_command()
        .args(["dev", "check"])
        .arg(&tools.project)
        .env("RSTACK_BREGCTL_BIN", &tools.bregctl)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("rstack install messaging"), "{stderr}");
    assert!(stderr.contains("RSTACK_MESSAGINGCTL_BIN"), "{stderr}");
    assert!(!stderr.contains("RSTACK_BREGCTL_BIN"), "{stderr}");
    assert!(!stderr.contains("RSTACK_MESSAGING_BIN"), "{stderr}");
}

#[test]
fn evidence_only_check_names_the_evidence_install_and_override() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["evidence"]);
    let output = tools
        .empty_command()
        .args(["dev", "check"])
        .arg(&tools.project)
        .env("RSTACK_BREGCTL_BIN", &tools.bregctl)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("rstack install evidence"), "{stderr}");
    assert!(stderr.contains("RSTACK_EVIDENCECTL_BIN"), "{stderr}");
    assert!(!stderr.contains("RSTACK_BREGCTL_BIN"), "{stderr}");
    assert!(!stderr.contains("RSTACK_EVIDENCE_BIN"), "{stderr}");
}

#[test]
fn run_id_actions_use_the_first_available_host_cli() {
    let tools = SourceTools::new();
    let missing = tools._scratch.path().join("not-installed");
    for action in [
        &["dev", "status", "run-1"][..],
        &["dev", "token", "run-1", "--as", "reviewer"][..],
        &["dev", "stop", "run-1"][..],
    ] {
        let casework_only = tools
            .empty_command()
            .args(action)
            .env("RSTACK_BREGCTL_BIN", missing.join("bregctl"))
            .env("RSTACK_CASEWORKCTL_BIN", &tools.caseworkctl)
            .output()
            .unwrap();
        assert!(casework_only.status.success(), "{casework_only:?}");
        assert_eq!(hosted(&casework_only).0, "caseworkctl", "{action:?}");

        let both = tools.command().args(action).output().unwrap();
        assert!(both.status.success(), "{both:?}");
        assert_eq!(hosted(&both).0, "bregctl", "{action:?}");
    }

    let none = tools
        .empty_command()
        .args(["dev", "status", "run-1"])
        .output()
        .unwrap();
    assert_eq!(none.status.code(), Some(1), "{none:?}");
    let stderr = String::from_utf8(none.stderr).unwrap();
    for text in [
        "rstack install breg",
        "rstack install casework",
        "RSTACK_BREGCTL_BIN",
        "RSTACK_CASEWORKCTL_BIN",
    ] {
        assert!(stderr.contains(text), "{stderr}");
    }
}

#[test]
fn managed_casework_plan_runs_through_the_installed_casework_cli() {
    let install = managed_install();
    write_plan(&install.project, &["casework"]);
    let output = Command::new(install.bin.join("rstack"))
        .arg("--install-root")
        .arg(&install.root)
        .arg("--bin-dir")
        .arg(&install.bin)
        .args(["dev", "check"])
        .arg(&install.project)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        hosted(&output),
        (
            "caseworkctl".to_owned(),
            runner_arguments("check", &[], &install.project)
        )
    );
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let generation = PathBuf::from(output_field(&stdout, "generation"));
    assert_eq!(
        PathBuf::from(output_field(&stdout, "caseworkctl")),
        generation.join("components/casework/caseworkctl/caseworkctl")
    );
}

#[test]
fn casework_plan_passes_casework_binaries_and_names_missing_installs() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["breg", "casework"]);
    let output = tools
        .command()
        .args(["dev", "start"])
        .arg(&tools.project)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        output_field(&stdout, "casework"),
        tools.casework.to_str().unwrap()
    );

    let missing = tools
        .empty_command()
        .args(["dev", "start"])
        .arg(&tools.project)
        .env("RSTACK_BREGCTL_BIN", &tools.bregctl)
        .env("RSTACK_BREG_BIN", &tools.breg)
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1), "{missing:?}");
    let stderr = String::from_utf8(missing.stderr).unwrap();
    assert!(stderr.contains("rstack install casework"), "{stderr}");
    assert!(!stderr.contains("rstack install breg"), "{stderr}");
    assert!(stderr.contains("RSTACK_CASEWORKCTL_BIN"), "{stderr}");
}

#[test]
fn missing_breg_names_the_install_command_before_the_overrides() {
    let tools = SourceTools::new();
    write_plan(&tools.project, &["breg", "casework"]);
    let output = tools
        .empty_command()
        .args(["dev", "start"])
        .arg(&tools.project)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let install = stderr
        .find("rstack install breg casework")
        .unwrap_or_else(|| panic!("{stderr}"));
    let overrides = stderr
        .find("RSTACK_BREGCTL_BIN")
        .unwrap_or_else(|| panic!("{stderr}"));
    assert!(install < overrides, "{stderr}");
}

#[test]
fn casework_text_outside_the_products_list_does_not_require_casework() {
    let tools = SourceTools::new();
    fs::write(
        tools.project.join("dev.yaml"),
        "# product: casework\nissuer: https://issuer.example\nproducts:\n  - {product: breg, project: breg, audience: \"urn:example:breg\"}\nscenarioFile: tests/scenarios.yaml\nnotes:\n  - name: \"product: casework\"\n",
    )
    .unwrap();
    let output = tools
        .empty_command()
        .args(["dev", "start"])
        .arg(&tools.project)
        .env("RSTACK_BREGCTL_BIN", &tools.bregctl)
        .env("RSTACK_BREG_BIN", &tools.breg)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

/// The host reports a plan the launcher cannot read with the positioned
/// diagnostics the configuration conformance corpus asserts, so the launcher
/// hands such a plan to the first available host instead of refusing it.
#[test]
fn unreadable_plan_is_reported_by_the_first_available_host() {
    let tools = SourceTools::new();
    let missing = tools._scratch.path().join("not-installed");
    for plan in [
        Some("products: [\n"),
        Some("issuer: https://issuer.example\n"),
        Some("products:\n  - {product: coordinator, project: c, audience: c}\n"),
        None,
    ] {
        match plan {
            Some(text) => fs::write(tools.project.join("dev.yaml"), text).unwrap(),
            None => fs::remove_file(tools.project.join("dev.yaml")).unwrap(),
        }
        for action in ["check", "start"] {
            let output = tools
                .empty_command()
                .args(["dev", action])
                .arg(&tools.project)
                .env("RSTACK_BREGCTL_BIN", missing.join("bregctl"))
                .env("RSTACK_CASEWORKCTL_BIN", &tools.caseworkctl)
                .output()
                .unwrap();
            assert!(output.status.success(), "{plan:?} {action}: {output:?}");
            assert_eq!(
                hosted(&output),
                (
                    "caseworkctl".to_owned(),
                    runner_arguments(action, &[], &tools.project)
                ),
                "{plan:?}"
            );
        }
    }
}
