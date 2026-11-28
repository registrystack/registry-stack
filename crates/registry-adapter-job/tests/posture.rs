// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn job_host_logs_posture_before_refusing_a_missing_store() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = directory.path().join("runtime.yaml");
    std::fs::write(
        &runtime,
        format!(
            "apiVersion: {}\nkind: {}\nid: lane-test\nendpoints: []\n",
            registry_adapter_core::ADAPTER_JOB_RUNTIME_API_VERSION,
            registry_adapter_core::ADAPTER_JOB_RUNTIME_KIND,
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_adapter-job"))
        .arg("init-store")
        .arg("--runtime")
        .arg(&runtime)
        .args(["--posture", "development"])
        .env_remove("REGISTRY_STACK_POSTURE")
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!output.status.success(), "{stderr}");
    let fields = stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|line| line["fields"]["message"] == "posture declared")
        .unwrap_or_else(|| panic!("startup did not log posture: {stderr}"));
    assert_eq!(fields["fields"]["posture"], "development");
    assert_eq!(fields["fields"]["posture_source"], "flag");
}

#[test]
fn job_store_reuses_the_shared_transport_rule() {
    use registry_adapter_engine::job_sources::JobRuntimeConfig;
    use registry_platform_config::{
        DeclaredPosture, Posture, PostureSource, RuntimeConfigLoader, RuntimeEnvelope,
        SecretProvider, SecretResolver,
    };
    use std::os::unix::fs::PermissionsExt;

    let mut development = DeclaredPosture {
        posture: Posture::Development,
        source: PostureSource::Flag,
    };
    let api_version = registry_adapter_core::ADAPTER_JOB_RUNTIME_API_VERSION;
    let kind = registry_adapter_core::ADAPTER_JOB_RUNTIME_KIND;
    let yaml = |transport, extra| {
        format!(
            "apiVersion: {api_version}\nkind: {kind}\nid: lane-test\nendpoints: []\nstore:\n  runtimeUrlRef: secret:file/job-db\n  transport: {transport}\n{extra}"
        )
    };
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let file = root.join("job-db");
    std::fs::write(&file, "postgresql://test@10.0.0.5/job").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let resolver = SecretResolver::new([SecretProvider::File], root).unwrap();
    let envelope = RuntimeEnvelope { api_version, kind };

    let parsed = RuntimeConfigLoader::new(envelope, development)
        .parse_str::<JobRuntimeConfig>(&yaml("private-network-plaintext", ""), |_| None)
        .unwrap();
    assert!(registry_adapter_job::store::build_pool_in_posture(
        parsed.config.store.as_ref().unwrap(),
        &resolver,
        parsed.development.as_ref(),
    )
    .is_ok());

    development.posture = Posture::Production;
    let production = RuntimeConfigLoader::new(envelope, development);
    let error = production
        .parse_str::<JobRuntimeConfig>(&yaml("private-network-plaintext", ""), |_| None)
        .unwrap_err();
    assert!(error.diagnostics().iter().any(|diagnostic| diagnostic.code
        == "platform.posture.database-private-plaintext"
        && diagnostic.path == "/store/transport"));

    for (extra, code) in [
        ("", "platform.database.transport-host-mismatch"),
        (
            "  testOnlyPlaintext: true\n",
            "platform.database.transport-conflict",
        ),
    ] {
        let parsed = production
            .parse_str::<JobRuntimeConfig>(&yaml("loopback-plaintext", extra), |_| None)
            .unwrap();
        let error = registry_adapter_job::store::build_pool(
            parsed.config.store.as_ref().unwrap(),
            &resolver,
        )
        .unwrap_err();
        assert!(error.to_string().contains(code), "{error}");
        assert!(error.to_string().contains("store.transport"), "{error}");
        assert!(
            !error.to_string().contains("write database.transport"),
            "{error}"
        );
    }
}

#[cfg(all(feature = "job-file", feature = "signed-coordinator-event"))]
#[test]
fn job_check_enforces_and_lists_the_posture() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/fixtures/corpus/base-job");
    let directory = tempfile::tempdir().unwrap();
    let runtime = directory.path().join("runtime.yaml");
    let yaml = std::fs::read_to_string(base.join("job-runtime.yaml")).unwrap();
    let destination = "\ndestinations:\n  coordinator-test:\n    type: signed-coordinator-event\n    baseUrl: http://127.0.0.1:9/events\n    hmacSha256KeyRef: secret:env/JOB_EVENT_KEY\n    attemptTimeoutMilliseconds: 1000\n";
    let run = |flag: Option<&str>, environment: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_adapter-job"));
        command
            .arg("check")
            .arg(base.join("job.yaml"))
            .arg("--pack")
            .arg(base.join("pack.yaml"))
            .arg("--runtime")
            .arg(&runtime);
        command.env_remove("REGISTRY_STACK_POSTURE");
        if let Some(flag) = flag {
            command.args(["--posture", flag]);
        }
        if let Some(environment) = environment {
            command.env("REGISTRY_STACK_POSTURE", environment);
        }
        command.output().unwrap()
    };
    std::fs::write(&runtime, format!("{yaml}{destination}store:\n  runtimeUrlRef: secret:env/JOB_DB\n  transport: private-network-plaintext\n")).unwrap();
    for flag in [None, Some("production")] {
        let output = run(flag, None);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        for expected in [
            "platform.posture.database-private-plaintext",
            "/store/transport",
            "store.transport selects an unencrypted connection to a private network; it is accepted only when the process declares development",
            "Write store.transport: verified-tls, and give the database a certificate the runtime trusts.",
            "REGISTRY_STACK_POSTURE=development",
            "--posture development",
        ] {
            assert!(stderr.contains(expected), "{stderr}");
        }
    }
    for (flag, environment) in [(Some("development"), None), (None, Some("development"))] {
        let output = run(flag, environment);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["posture"],
            serde_json::json!({
                "value": "development",
                "source": if flag.is_some() { "flag" } else { "environment" }
            })
        );
        assert_eq!(
            report["developmentSettings"],
            serde_json::json!([{
                "code": "platform.posture.database-private-plaintext",
                "pointer": "/store/transport"
            }])
        );
        assert_eq!(
            report["explicitProductionSettings"],
            serde_json::json!([{
                "code": "adapter.posture.anonymous-https",
                "pointer": "/endpoints/0/anonymousHttps"
            }])
        );
    }
    std::fs::write(&runtime, format!("{yaml}{destination}store:\n  runtimeUrlRef: secret:env/JOB_DB\n  transport: loopback-plaintext\n")).unwrap();
    let output = run(None, None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["posture"],
        serde_json::json!({"value": "production", "source": "default"})
    );
    std::fs::write(&runtime, format!("{yaml}{destination}store:\n  runtimeUrlRef: secret:env/JOB_DB\n  transport: loopback-plaintext\n  testOnlyPlaintext: true\n")).unwrap();
    let output = run(None, None);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    for expected in [
        "platform.database.transport-conflict",
        "/store/transport",
        "store.transport and store.testOnlyPlaintext are both set",
        "Remove store.testOnlyPlaintext, and keep store.transport.",
    ] {
        assert!(stderr.contains(expected), "{stderr}");
    }
}
