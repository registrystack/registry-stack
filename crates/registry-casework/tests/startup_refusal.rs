//! A `casework` that refuses its runtime file or its packaged project at
//! startup prints the reader's CFG-DIAG-2 lines to stderr unchanged, after
//! one sentence of its own, before it opens a database.

use std::path::Path;
use std::process::Command;

use registry_casework::{
    package_limits, PACKAGE_COMMAND, POLICY_FILE, RUNTIME_CONFIG_API_VERSION, RUNTIME_CONFIG_KIND,
};

const PROJECT: &str =
    include_str!("../../../products/casework/examples/standalone-decision/casework.yaml");

fn write_runtime(root: &Path, package: &Path) -> std::path::PathBuf {
    write_runtime_with(root, package, "casework-test", "127.0.0.1:8100", "")
}

fn write_runtime_with(
    root: &Path,
    package: &Path,
    database_id: &str,
    bind: &str,
    tail: &str,
) -> std::path::PathBuf {
    let runtime = root.join("runtime.yaml");
    std::fs::write(
        &runtime,
        format!(
            "apiVersion: {RUNTIME_CONFIG_API_VERSION}
kind: {RUNTIME_CONFIG_KIND}
identity: {{databaseId: \"{database_id}\"}}
package: {{root: {package}}}
listener: {{bind: \"{bind}\", tlsTermination: loopback-plaintext}}
secretProviders: {{file: {{root: {root}/secrets}}, environment: {{}}}}
database: {{runtimeUrlRef: secret:env/RUNTIME, migrationUrlRef: secret:env/MIGRATION}}
authentication: {{oidc: {{issuer: http://127.0.0.1:8091, audience: urn:example:casework, allowedClients: [casework-test]}}}}
audit: {{path: {root}/audit.ndjson, hashKeyRef: secret:file/audit}}
contextProviders: {{}}
{tail}",
            package = package.display(),
            root = root.display(),
        ),
    )
    .expect("write runtime.yaml");
    runtime
}

#[test]
fn a_refused_project_prints_every_reader_line_to_stderr() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical root");
    let package = root.join("package");
    std::fs::create_dir(&package).expect("package directory");
    let project = PROJECT.replace(
        "    label: Decisions awaiting review\n",
        "    label: Decisions awaiting review\n    lable: Decisions\n",
    ) + "queuez: []\n";
    assert_ne!(project, PROJECT);
    std::fs::write(package.join(POLICY_FILE), &project).expect("write casework.yaml");
    registry_platform_config::write_sum_file(&package, None, &package_limits(), PACKAGE_COMMAND)
        .expect("write SHA256SUMS");
    let runtime = write_runtime(&root, &package);

    let output = Command::new(env!("CARGO_BIN_EXE_casework"))
        .arg("--runtime-config")
        .arg(&runtime)
        .arg("serve")
        .env_remove("CASEWORK_LOG")
        .output()
        .expect("run casework");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    // Captured package diagnostics name the verified package member, rather
    // than an ambient path that would be read again after verification.
    let policy = POLICY_FILE;
    let label_line = project
        .lines()
        .position(|line| line == "    lable: Decisions")
        .expect("lable line")
        + 1;
    let queuez_line = project.lines().count();
    let expected = format!(
        "casework: the Casework project is invalid
error[config.unknown-key] {policy}:{label_line}:5 /queues/decisions/lable
  `lable` is not a member of this mapping
  next: Rename `lable` to `label`, or remove it.
error[config.unknown-key] {policy}:{queuez_line}:1 /queuez
  `queuez` is not a member of this mapping
  next: Rename `queuez` to `queues`, or remove it.
2 errors, 0 warnings in 1 file
",
        policy = policy,
    );
    assert_eq!(stderr, expected);
}

fn serve(runtime: &Path) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_casework"))
        .arg("--runtime-config")
        .arg(runtime)
        .arg("serve")
        .env_remove("CASEWORK_LOG")
        .output()
        .expect("run casework");
    assert!(output.stdout.is_empty());
    (
        output.status.code(),
        String::from_utf8(output.stderr).expect("UTF-8 stderr"),
    )
}

#[test]
fn a_refused_runtime_file_prints_every_reader_line_to_stderr() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical root");
    let package = root.join("package");
    let runtime = write_runtime_with(
        &root,
        &package,
        "casework-test",
        "127.0.0.1:8100",
        "unknownOne: 1\nunknownTwo: 2\n",
    );

    let (code, stderr) = serve(&runtime);

    assert_eq!(code, Some(1));
    let text = std::fs::read_to_string(&runtime).expect("read runtime.yaml");
    let line_of = |key: &str| {
        text.lines()
            .position(|line| line.starts_with(key))
            .expect("key line")
            + 1
    };
    let expected = format!(
        "casework: the Casework runtime configuration was refused
error[config.unknown-key] {runtime}:{one}:1 /unknownOne
  `unknownOne` is not a member of this mapping
  next: Remove `unknownOne`; the accepted keys are {accepted}.
error[config.unknown-key] {runtime}:{two}:1 /unknownTwo
  `unknownTwo` is not a member of this mapping
  next: Remove `unknownTwo`; the accepted keys are listed at line {one}.
2 errors, 0 warnings in 1 file
",
        runtime = runtime.display(),
        one = line_of("unknownOne"),
        two = line_of("unknownTwo"),
        accepted = "`apiVersion`, `kind`, `identity`, `package`, `listener`, \
            `metricsListener`, `secretProviders`, `database`, `authentication`, `audit`, \
            `taskAuthority`, `contextProviders`, `reviewCompletionDestinations`",
    );
    assert_eq!(stderr, expected);
}

#[test]
fn a_runtime_file_breaking_casework_rules_prints_each_at_its_position() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical root");
    let package = root.join("package");
    let runtime = write_runtime_with(&root, &package, " padded ", "10.0.0.5:8100", "");

    let (code, stderr) = serve(&runtime);

    assert_eq!(code, Some(1));
    let runtime = runtime.display();
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(
        lines[0],
        "casework: the Casework runtime configuration was refused"
    );
    assert_eq!(
        lines[1],
        format!("error[casework.runtime.invalid-database-id] {runtime}:3:24 /identity/databaseId")
    );
    assert_eq!(
        lines[4],
        format!("error[casework.runtime.invalid-listener] {runtime}:5:18 /listener/bind")
    );
    assert_eq!(lines[7], "2 errors, 0 warnings in 1 file");
    assert!(!stderr.contains("padded"), "{stderr}");
    assert!(!stderr.contains("10.0.0.5"), "{stderr}");
}

fn assert_completion_credential_names_replacement(member: &str, value: &str) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path().canonicalize().expect("canonical root");
    let runtime = write_runtime_with(
        &root,
        &root.join("package"),
        "casework-test",
        "127.0.0.1:8100",
        &format!("reviewCompletionDestinations:\n  receiver:\n    url: https://receiver.example.test/completions\n    {member}: {value}\n"),
    );

    let (code, stderr) = serve(&runtime);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains(&format!("/reviewCompletionDestinations/receiver/{member}")),
        "{stderr}"
    );
    assert!(
        stderr.contains("Configure hmacSha256KeyRef with a Standard Webhooks signing key"),
        "{stderr}"
    );
    assert!(!stderr.contains("secret:file/retired"), "{stderr}");
}

#[test]
fn a_completion_destination_with_a_bearer_token_names_its_replacement() {
    assert_completion_credential_names_replacement("bearerTokenRef", "secret:file/retired");
}

#[test]
fn a_completion_destination_with_auth_names_its_replacement() {
    assert_completion_credential_names_replacement(
        "auth",
        "{header: x-api-key, secretRef: secret:file/retired}",
    );
}

const CANONICAL: &str =
    include_str!("../../../products/casework/examples/canonical-review/casework.yaml");
const CANONICAL_SCHEMA: &str = include_str!(
    "../../../products/casework/examples/canonical-review/schemas/correct-address.schema.json"
);

#[test]
fn a_breg_task_grant_context_provider_without_runtime_profile_is_refused_by_name() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical root");
    let package = root.join("package");
    std::fs::create_dir_all(package.join("schemas")).expect("package directory");
    std::fs::create_dir(root.join("secrets")).expect("secrets directory");
    let project = CANONICAL
        .replace(
            "    capabilities: [human-display, service-status]\n",
            "    description: context-providers/facility-proposal-context.json
    capabilities: [human-display, service-status, task-grant-context]\n",
        )
        .replace(
            "      service-status: casework-review-status\n",
            "      service-status: casework-review-status\n      task-grant-context: casework-task-context\n",
        )
        + "teams:
  facility-reviewers:
    label: Facility reviewers
    serves: [facility-addresses]
    memberProfiles: [staff]
    supervisorProfiles: [supervisor]
taskTemplates:
  address-summary:
    version: \"1\"
    label: Prepare an address summary
    eligibleTeams: [facility-reviewers]
    eligibleProfiles: [staff]
    source: facility-registry
    reviewPolicies: [facility-address-review]
    agent: {issuer: http://127.0.0.1:8091, subject: summary-agent}
    client: summary-client
    resource: urn:breg:facility-registry
    scopes: [registry:facility:read]
    purpose: prepare-summary
    bounds: {type: breg, permissions: [{collection: facilities, operations: [get]}]}
    subjects: {facility: facilityId}
    lifetimeSeconds: 900
";
    assert!(project.contains("task-grant-context: casework-task-context"));
    std::fs::write(package.join(POLICY_FILE), &project).expect("write casework.yaml");
    std::fs::write(
        package.join("schemas/correct-address.schema.json"),
        CANONICAL_SCHEMA,
    )
    .expect("write schema");
    // The export `caseworkctl provider pair` captures from BReg for the
    // canonical review: the same schema bytes the policy pins.
    let schema: serde_json::Value = serde_json::from_str(CANONICAL_SCHEMA).expect("schema");
    let context = &schema["x-registry-review-context"];
    let export = serde_json::json!({
        "apiVersion": registry_casework_breg::DESCRIPTION_API_VERSION,
        "kind": registry_casework_breg::DESCRIPTION_KIND,
        "sourceNamespace": "facility-registry",
        "actionId": context["actionId"],
        "contextId": context["contextId"],
        "contract": {
            "id": schema["$id"],
            "revision": schema["x-registry-definition-revision"],
            "schemaDigest": registry_platform_config::sha256_uri(CANONICAL_SCHEMA.as_bytes()),
        },
        "schema": schema,
        "schemaBytes": CANONICAL_SCHEMA,
    });
    std::fs::create_dir(package.join("context-providers")).expect("export directory");
    std::fs::write(
        package.join("context-providers/facility-proposal-context.json"),
        serde_json::to_vec(&export).expect("export bytes"),
    )
    .expect("write export");
    registry_platform_config::write_sum_file(&package, None, &package_limits(), PACKAGE_COMMAND)
        .expect("write SHA256SUMS");
    let runtime = write_runtime(&root, &package);
    let text = std::fs::read_to_string(&runtime)
        .expect("read runtime.yaml")
        .replace(
            "allowedClients: [casework-test]",
            "allowedClients: [summary-client]",
        )
        .replace(
            "contextProviders: {}\n",
            "contextProviders:
  facility-registry:
    baseUrl: https://registry.example.test
    statusProfile: casework-review-status
    # The provider declares a distinct task-grant-context service profile, so
    # startup must refuse this binding while taskGrantProfile is absent.
    tokenEndpoint: https://identity.example.test/oauth2/token
    clientAssertionAudience: https://identity.example.test
    resource: urn:breg:facility-registry
    scopes: [registry:proposal:review-status]
    clientIdRef: secret:file/breg-status-client-id
    clientAssertionKeyRef: secret:file/breg-status-client-key
taskAuthority:
  issuer: https://casework.example.test
  exchangeAudience: urn:example:exchange
  signingKeyRef: secret:file/task-signer
  statusClients: {}
",
        );
    std::fs::write(&runtime, text).expect("write runtime.yaml");

    let loaded = registry_casework::RuntimeConfig::load(
        &runtime,
        registry_platform_config::DeclaredPosture {
            posture: registry_platform_config::Posture::Development,
            source: registry_platform_config::PostureSource::Flag,
        },
    )
    .expect("runtime file");
    let config = loaded.config;
    let package = config.load_package().expect("package");
    let secrets = registry_casework::secret_resolver(&config).expect("secrets");
    let error = registry_casework::build_context_providers(&config, &package, &secrets)
        .err()
        .expect("runtime binding omits the required task-grant profile");

    assert!(matches!(
        &error,
        registry_casework::RuntimeError::ContextProviderConfiguration(provider)
            if provider == "facility-proposal-context"
    ));
    assert_eq!(
        error.to_string(),
        "the Casework review-context provider facility-proposal-context is not configured for its declared capability and export"
    );
}

#[test]
fn production_collects_development_settings_before_opening_the_package() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = directory.path().canonicalize().expect("canonical root");
    let runtime = write_runtime(&root, &root.join("absent-package"));
    let contents = std::fs::read_to_string(&runtime).expect("runtime file");
    std::fs::write(
        &runtime,
        contents
            .replace(
                "issuer: http://127.0.0.1:8091",
                "issuer: http://10.0.0.5:8091, allowInsecureHttp: true",
            )
            .replace(
                "allowedClients: [casework-test]",
                "allowedClients: unrestricted",
            ),
    )
    .expect("write runtime file");

    for posture in [None, Some("production")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_casework"));
        command.env_remove("REGISTRY_STACK_POSTURE");
        command.arg("--runtime-config").arg(&runtime);
        if let Some(value) = posture {
            command.args(["--posture", value]);
        }
        let output = command.arg("serve").output().expect("run casework");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
        for needle in [
            "platform.posture.insecure-issuer-http",
            "casework.posture.unrestricted-clients",
            "/authentication/oidc/allowedClients",
            "rstack dev",
            "REGISTRY_STACK_POSTURE=development",
            "--posture development",
        ] {
            assert!(stderr.contains(needle), "missing {needle}: {stderr}");
        }
        assert_eq!(output.status.code(), Some(1));
    }
}

#[test]
fn development_startup_logs_the_settings_before_opening_dependencies() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let package = root.join("package");
    std::fs::create_dir(&package).unwrap();
    std::fs::write(package.join(POLICY_FILE), PROJECT).unwrap();
    registry_platform_config::write_sum_file(&package, None, &package_limits(), PACKAGE_COMMAND)
        .unwrap();
    let runtime = write_runtime(&root, &package);
    let contents = std::fs::read_to_string(&runtime).unwrap().replace(
        "issuer: http://127.0.0.1:8091, audience: urn:example:casework, allowedClients: [casework-test]",
        "issuer: http://10.0.0.5:8091, allowInsecureHttp: true, audience: urn:example:casework, allowedClients: unrestricted",
    );
    std::fs::write(&runtime, contents).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_casework"))
        .arg("--runtime-config")
        .arg(&runtime)
        .args(["--posture", "development", "serve"])
        .env_remove("REGISTRY_STACK_POSTURE")
        .env_remove("CASEWORK_LOG")
        .output()
        .unwrap();
    let lines = String::from_utf8(output.stdout).unwrap();
    let logs: Vec<serde_json::Value> = lines
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        logs.iter()
            .any(|log| log["fields"]["message"] == "posture declared"
                && log["fields"]["posture"] == "development"
                && log["fields"]["development_settings"] == 2),
        "{lines}"
    );
    for code in [
        "platform.posture.insecure-issuer-http",
        "casework.posture.unrestricted-clients",
    ] {
        assert!(
            logs.iter().any(|log| log["fields"]["error_code"] == code),
            "{lines}"
        );
    }
}

#[test]
fn invalid_posture_is_a_usage_error_before_runtime_loading() {
    let output = Command::new(env!("CARGO_BIN_EXE_casework"))
        .args([
            "--posture",
            "bogus",
            "--runtime-config",
            "/unused/runtime.yaml",
            "serve",
        ])
        .env_remove("REGISTRY_STACK_POSTURE")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "casework: [platform.posture.invalid-value] --posture was given a value that is not a posture\n  next: Pass --posture development or --posture production.\n"
    );
}
