//! Operator refusals retain exact recovery and never disclose credentials or change references.
use super::*;
use registry_casework::{ActivationError, ActivationRefusal, StoreError};

#[test]
fn activation_refusals_keep_each_code_and_audit_failures_distinguish_commit() {
    let error = anyhow::Error::new(ActivationError::Refused(vec![
        ActivationRefusal {
            code: "casework.activation.schema-newer".into(),
            path: "database".into(),
            message: "the schema is newer than this binary supports".into(),
        },
        ActivationRefusal {
            code: "casework.activation.retired-schema".into(),
            path: "database".into(),
            message: "preserve the retired database".into(),
        },
    ]));
    let (exit, diagnostics) = activation_failure(&error).unwrap();
    assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(diagnostics[0].code, "casework.activation.schema-newer");
    assert!(diagnostics[0].suggested_action.contains("supports"));
    let refusal = anyhow::Error::new(ActivationError::Store(StoreError::AuditUnavailable));
    let (exit, diagnostics) = activation_failure(&refusal).unwrap();
    assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
    assert_eq!(diagnostics[0].code, "casework.activation.audit-unavailable");
    assert!(diagnostics[0].message.contains("not applied"));
    let committed = anyhow::Error::new(ActivationError::AppliedUnaudited {
        activation_id: uuid::Uuid::new_v4(),
        package_digest: format!("sha256:{}", "a".repeat(64)),
    });
    let (exit, diagnostics) = activation_failure(&committed).unwrap();
    assert_eq!(exit, OPERATIONAL_FAILURE_EXIT);
    assert_eq!(diagnostics[0].code, "casework.activation.applied-unaudited");
    assert!(diagnostics[0]
        .suggested_action
        .contains("package is active"));
    assert!(diagnostics[0].suggested_action.contains("status"));
}

#[test]
fn unreadable_ledger_names_apply_without_echoing_database_schema() {
    for error in [
        anyhow::Error::new(StoreError::LedgerUnreadable {
            schema: "PRIVATE_SCHEMA_CANARY".into(),
        }),
        anyhow::Error::new(ActivationError::Store(StoreError::LedgerUnreadable {
            schema: "PRIVATE_SCHEMA_CANARY".into(),
        })),
    ] {
        let (exit, diagnostics) = activation_failure(&error).unwrap();
        assert_eq!(exit, DOMAIN_REFUSAL_EXIT);
        assert_eq!(diagnostics[0].code, "casework.activation.ledger-unreadable");
        assert!(diagnostics[0]
            .suggested_action
            .contains("caseworkctl apply"));
        assert!(!serde_json::to_string(&diagnostics)
            .unwrap()
            .contains("PRIVATE_SCHEMA_CANARY"));
    }
}

#[cfg(all(feature = "postgres-test", unix))]
fn execute(url: &str, sql: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
                .await
                .expect("connect disposable operator database");
            tokio::spawn(async move { connection.await.expect("operator database connection") });
            client.batch_execute(sql).await.expect("operator test SQL");
        });
}

#[cfg(all(feature = "postgres-test", unix))]
#[test]
fn apply_reports_a_schema_newer_than_this_binary_with_its_own_refusal() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let base = std::env::var("CASEWORK_REVIEW_TEST_DATABASE_URL")
        .expect("disposable review database required");
    let schema = format!("operator_{}", uuid::Uuid::new_v4().simple());
    execute(&base, &format!("CREATE SCHEMA {schema}"));
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let secret =
        format!("CASEWORKCTL_OPERATOR_{}", uuid::Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&secret, &scoped);
    struct Cleanup {
        base: String,
        schema: String,
        secret: String,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            execute(&self.base, &format!("DROP SCHEMA {} CASCADE", self.schema));
            std::env::remove_var(&self.secret);
        }
    }
    let _cleanup = Cleanup {
        base: base.clone(),
        schema,
        secret: secret.clone(),
    };
    let directory = canonical_tempdir();
    let project = directory.path().join("standalone");
    project::init(&project, "standalone-decision").unwrap();
    project::package(
        &project,
        &project.join(project::LOCAL_PACKAGE_DIRECTORY),
        None,
    )
    .unwrap();
    let secrets = project.join("secrets");
    std::fs::create_dir(&secrets).unwrap();
    let audit_key = secrets.join("casework-audit-key");
    std::fs::write(&audit_key, "0".repeat(64)).unwrap();
    std::fs::set_permissions(&audit_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(project.join("state"))
        .unwrap();
    let mut runtime = registry_platform_yaml::Reader::new("runtime.example.yaml")
        .scan(&std::fs::read(project.join("runtime.example.yaml")).unwrap())
        .unwrap()
        .expect("the maintained runtime fixture is not empty")
        .to_json_value();
    runtime["secretProviders"]["environment"] = json!({});
    runtime["authentication"]["oidc"]["allowedClients"] = json!(["operator-test"]);
    runtime["database"] = json!({"runtimeUrlRef":format!("secret:env/{secret}"),"migrationUrlRef":format!("secret:env/{secret}"),"testOnlyPlaintext":true});
    let config = project.join("runtime.yaml");
    std::fs::write(&config, serde_norway::to_string(&runtime).unwrap()).unwrap();
    let invoke = |command: &str, posture: &str, extra: &[&str]| {
        let mut args = vec![
            OsString::from("caseworkctl"),
            OsString::from("--format"),
            OsString::from("json"),
            OsString::from(command),
            OsString::from("--runtime-config"),
            config.as_os_str().to_owned(),
            OsString::from("--posture"),
            OsString::from(posture),
        ];
        args.extend(extra.iter().map(OsString::from));
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let exit = main_entry_from(args, &mut stdout, &mut stderr);
        assert!(
            stderr.is_empty(),
            "JSON diagnostics must be part of the report on stdout"
        );
        let report: Value = serde_json::from_slice(&stdout).expect("typed JSON operator report");
        assert_eq!(report["kind"], "CaseworkReport");
        #[cfg(feature = "schema")]
        {
            let documents = crate::schema::report_documents().unwrap();
            let schema: Value = serde_json::from_str(&documents["report.schema.json"]).unwrap();
            let validator = jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .compile(&schema)
                .unwrap();
            if let Err(errors) = validator.validate(&report) {
                panic!(
                    "operator report schema mismatch at {}",
                    errors
                        .map(|error| error.instance_path.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            };
        }

        assert!(!report.to_string().contains(&scoped));
        assert!(!report.to_string().contains("CHANGE_REFERENCE_CANARY"));
        (exit, report)
    };
    let (exit, plan) = invoke("plan", "development", &[]);
    assert_eq!(exit, ExitCode::SUCCESS, "{plan:?}");
    assert_eq!(plan["plan"]["planKind"], "initial");
    let (exit, applied) = invoke(
        "apply",
        "development",
        &["--operator-reference", "CHANGE_REFERENCE_CANARY"],
    );
    assert_eq!(exit, ExitCode::SUCCESS, "{applied:?}");
    assert!(!applied["schemaVersionsApplied"]
        .as_array()
        .unwrap()
        .is_empty());
    let (exit, status) = invoke("status", "development", &[]);
    assert_eq!(exit, ExitCode::SUCCESS, "{status:?}");
    let (exit, replan) = invoke("plan", "development", &[]);
    assert_eq!(exit, ExitCode::SUCCESS, "{replan:?}");
    assert_eq!(replan["plan"]["changesPending"], false);
    assert_eq!(
        status["posture"],
        json!({"value": "development", "source": "flag"})
    );
    let (exit, opposite_status) = invoke("status", "production", &[]);
    assert_eq!(exit, ExitCode::SUCCESS, "{opposite_status:?}");
    assert_eq!(
        opposite_status["diagnostics"][0]["code"],
        "platform.activation.posture-mismatch"
    );
    assert_eq!(
        opposite_status["activation"]["history"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let (exit, opposite_doctor) = invoke("doctor", "production", &[]);
    assert_eq!(
        exit,
        ExitCode::from(DOMAIN_REFUSAL_EXIT),
        "{opposite_doctor:?}"
    );
    assert!(opposite_doctor["activation"]["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .any(|refusal| refusal["code"] == "platform.activation.posture-mismatch"));
    let supported = status["activation"]["supportedSchemaVersion"]
        .as_i64()
        .unwrap();
    execute(
        &scoped,
        &format!(
            "INSERT INTO casework_schema_migrations(version,applied_at) VALUES({},now())",
            supported + 1
        ),
    );
    let (exit, refused) = invoke("apply", "development", &[]);
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{refused:?}");
    assert_eq!(refused["status"], "domain-refusal");
    assert_eq!(
        refused["diagnostics"][0]["code"],
        "casework.activation.schema-newer"
    );
    assert_eq!(refused["diagnostics"][0]["path"], "database");
    assert_eq!(
        refused["diagnostics"][0]["message"],
        StoreError::SchemaNewer {
            found: supported + 1,
            supported
        }
        .to_string()
    );
    assert!(refused["diagnostics"][0]["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("supports"));
    let (exit, plan) = invoke("plan", "development", &[]);
    assert_eq!(exit, ExitCode::from(DOMAIN_REFUSAL_EXIT), "{plan:?}");
    assert_eq!(
        plan["diagnostics"][0]["code"],
        "casework.activation.schema-newer"
    );
}

#[test]
fn plan_refusals_preserve_actionable_schema_recovery() {
    let diagnostic = crate::report::operator_refusal_diagnostic(
        "casework.activation.schema-newer",
        "database",
        "newer schema",
    );
    assert!(diagnostic
        .suggested_action
        .contains("supports this database schema"));
}

#[test]
fn check_rejects_contradictory_posture_flags() {
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let exit = main_entry_from(
        [
            "caseworkctl",
            "--format",
            "json",
            "check",
            ".",
            "--production",
            "--posture",
            "development",
        ]
        .map(OsString::from),
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, ExitCode::from(report::USAGE_EXIT));
    assert!(stderr.is_empty());
    let value: Value = serde_json::from_slice(&stdout).unwrap();
    let diagnostic = &value["diagnostics"][0];
    assert_eq!(diagnostic["code"], "platform.posture.conflict");
    assert_eq!(
        diagnostic["message"],
        "--production and --posture development contradict each other"
    );
    assert_eq!(diagnostic["suggestedAction"], "Use one of them.");
}

#[test]
fn a_check_acceptance_cannot_hide_a_development_setting() {
    let root = canonical_tempdir();
    let project = root.path().join("project");
    project::init(&project, "standalone-decision").unwrap();
    std::fs::write(
        project.join("check-acceptances.yaml"),
        r#"apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1
kind: PlatformCheckAcceptances
acceptances:
  - code: casework.posture.unrestricted-clients
    scope:
      file: runtime.example.yaml
      path: /authentication/oidc/allowedClients
    reason: A local acceptance must not hide this warning.
"#,
    )
    .unwrap();
    let result = project::check_runtime_config(
        &project,
        &project.join("runtime.example.yaml"),
        false,
        false,
        project::check(&project, false, false),
        DeclaredPosture {
            posture: registry_platform_config::Posture::Development,
            source: registry_platform_config::PostureSource::Flag,
        },
    );
    let error = result.unwrap_err();
    let diagnostics = configuration_report(&error).unwrap().diagnostics();
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "config.check-acceptance-not-acceptable"));
    assert!(diagnostics.iter().any(|diagnostic| diagnostic.code
        == "casework.posture.unrestricted-clients"
        && diagnostic.severity == registry_platform_yaml::Severity::Warning));
}
