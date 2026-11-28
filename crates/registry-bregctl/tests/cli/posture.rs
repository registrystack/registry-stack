// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn opposite_activation_posture_refuses_planning_and_apply_and_reports_findings() {
    let root_url = std::env::var("BREG_TEST_DATABASE_URL")
        .expect("set BREG_TEST_DATABASE_URL for the posture PostgreSQL test");
    let root_url = url::Url::parse(&root_url).expect("the test PostgreSQL URL parses");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (admin, connection) = tokio_postgres::connect(root_url.as_str(), tokio_postgres::NoTls)
            .await
            .expect("connect to disposable PostgreSQL");
        let owner = tokio::spawn(connection);
        for (recorded, declared) in [("production", "development"), ("development", "production")] {
            let database = format!("breg_ctl_posture_{}", uuid::Uuid::new_v4().simple());
            let role = format!("{database}_role");
            admin
                .batch_execute(&format!(
                    "CREATE ROLE {role} LOGIN PASSWORD 'synthetic-posture-fixture';"
                ))
                .await
                .unwrap();
            admin
                .batch_execute(&format!("CREATE DATABASE {database}"))
                .await
                .unwrap();
            admin
                .batch_execute(&format!(
                    "GRANT CONNECT, TEMPORARY ON DATABASE {database} TO {role}"
                ))
                .await
                .unwrap();
            let mut database_url = root_url.clone();
            database_url.set_path(&format!("/{database}"));
            let (database_admin, connection) =
                tokio_postgres::connect(database_url.as_str(), tokio_postgres::NoTls)
                    .await
                    .unwrap();
            let database_owner = tokio::spawn(connection);
            registry_breg::postgres::provision_managed_schemas(
                &database_admin,
                &registry_breg::postgres::SqlIdentifier::parse(&role).unwrap(),
            )
            .await
            .unwrap();
            drop(database_admin);
            database_owner.await.unwrap().unwrap();
            database_url.set_username(&role).unwrap();
            database_url
                .set_password(Some("synthetic-posture-fixture"))
                .unwrap();
            let result = std::panic::catch_unwind(|| {
                let project = packaging_project();
                let package = project.path().join("package");
                fs::create_dir(&package).unwrap();
                let config_root = tempfile::tempdir().unwrap();
                let config = write_runtime_config(
                    config_root.path(),
                    &package,
                    "127.0.0.1:1".parse().unwrap(),
                );
                let source = fs::read_to_string(&config).unwrap();
                fs::write(
                    &config,
                    source
                        .replace(
                            "  runtimeUrlRef:",
                            "  transport: loopback-plaintext\n  runtimeUrlRef:",
                        )
                        .replace(
                            "migration: registry_migration",
                            &format!("migration: {role}"),
                        )
                        .replace("runtime: registry_runtime", &format!("runtime: {role}"))
                        .replace("principal: registry_principal", "principal: principal")
                        .replace("    purpose: registry_purpose\n", "")
                        .replace(
                            "    jwksCache:\n",
                            "    jwksSource:\n      type: static\n      documentRef: secret:file/oidc-jwks\n    jwksCache:\n",
                        ),
                )
                .unwrap();
                use std::io::Write as _;
                use std::os::unix::fs::OpenOptionsExt as _;
                fs::create_dir(config_root.path().join("audit")).unwrap();
                fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(
                        config_root
                            .path()
                            .join("secrets")
                            .join(PACKAGE_VALUE_CANARY),
                    )
                    .unwrap()
                    .write_all(&[7; 32])
                    .unwrap();
                fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(config_root.path().join("secrets/oidc-jwks"))
                    .unwrap()
                    .write_all(br#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"synthetic-doctor-jwks"}]}"#)
                    .unwrap();
                let run = |args: &[&str]| {
                    Command::new(env!("CARGO_BIN_EXE_bregctl"))
                        .args(["--format", "json"])
                        .args(args)
                        .env_remove("REGISTRY_STACK_POSTURE")
                        .env(
                            VERIFY_MIGRATION_DATABASE_SECRET_CANARY,
                            database_url.as_str(),
                        )
                        .env(VERIFY_RUNTIME_DATABASE_SECRET_CANARY, database_url.as_str())
                        .output()
                        .unwrap()
                };
                let measured = run(&[
                    "test",
                    path(project.path()),
                    "--runtime-config",
                    path(&config),
                    "--fingerprint-only",
                ]);
                assert!(measured.status.success(), "{}", json_stdout(&measured));
                let measured = json_stdout(&measured);
                let prepared = prepare_packaging_candidate(
                    &project,
                    measured["schemaFingerprint"].as_str().unwrap(),
                );
                fs::remove_dir(&package).unwrap();
                prepared.publish_to_directory(&package).unwrap();
                let before = run(&[
                    "apply",
                    "--initial",
                    "--runtime-config",
                    path(&config),
                    "--package",
                    path(&package),
                    "--posture",
                    recorded,
                ]);
                assert!(before.status.success(), "{}", json_stdout(&before));
                let status = |posture| {
                    run(&[
                        "status",
                        "--runtime-config",
                        path(&config),
                        "--posture",
                        posture,
                    ])
                };
                let before = json_stdout(&status(recorded));
                let unopened_audit = config_root.path().join("audit/must-stay-absent.jsonl");
                let apply_config = config_root.path().join("refused-apply.yaml");
                let source = fs::read_to_string(&config).unwrap();
                fs::write(&apply_config, source.replace("audit.jsonl", "must-stay-absent.jsonl")).unwrap();
                for operation in ["plan", "apply"] {
                    let mut args = vec![
                        operation,
                        "--runtime-config",
                        path(if operation == "apply" { &apply_config } else { &config }),
                        "--package",
                        path(&package),
                        "--posture",
                        declared,
                    ];
                    if operation == "apply" {
                        args.push("--initial");
                    }
                    let refused = run(&args);
                    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
                    let report = json_stdout(&refused);
                    assert_eq!(
                        report["diagnostics"][0]["code"], "breg.activation.posture-mismatch",
                        "{report}"
                    );
                }
                assert!(!unopened_audit.exists(), "a posture refusal must precede opening audit");
                let checked = status(declared);
                assert!(checked.status.success(), "{checked:?}");
                let checked = json_stdout(&checked);
                assert_eq!(
                    checked["diagnostics"][0]["code"], "breg.activation.posture-mismatch",
                    "{checked}"
                );
                assert_eq!(checked["ledger"], before["ledger"]);
                if declared == "development" {
                    let source = fs::read_to_string(&config).unwrap();
                    fs::write(&config, source.replace(
                        "  bind: 127.0.0.1:1\n",
                        "  bind: 127.0.0.1:1\n  publicOrigin: http://127.0.0.1:1\n",
                    )).unwrap();
                }
                let doctor = run(&[
                    "doctor",
                    "--runtime-config",
                    path(&config),
                    "--posture",
                    declared,
                ]);
                assert!(doctor.status.success(), "{}", json_stdout(&doctor));
                let doctor_report = json_stdout(&doctor);
                assert!(doctor_report["checked"].is_array(), "{doctor_report}");
                assert!(doctor_report["roleMode"].is_string(), "{doctor_report}");
                assert!(doctor_report["advisories"].is_array(), "{doctor_report}");
                let has_code = |member: &str, code: &str| {
                    doctor_report[member].as_array().unwrap().iter().any(|item| item["code"] == code)
                };
                assert!(has_code("diagnostics", "breg.activation.posture-mismatch"), "{doctor_report}");
                assert!(has_code("advisories", "breg.activation.posture-mismatch"), "{doctor_report}");
                if declared == "development" {
                    assert!(has_code("advisories", "breg.posture.http-public-origin"), "{doctor_report}");
                }
                let refresh_config = config_root.path().join("invalid-refresh.yaml");
                let source = fs::read_to_string(&config).unwrap();
                fs::write(&refresh_config, format!("{source}
externalRefresh:
  plans:
    people:
      target: {{view: unknown-view, link: register}}
      worker:
        accessProfile: person-refresh
        requesterClient: wfp-scope
        principal: refresh-service
      intervalSeconds: 60
")).unwrap();
                let refresh_doctor = run(&[
                    "doctor", "--runtime-config", path(&refresh_config), "--posture", declared,
                ]);
                assert_eq!(refresh_doctor.status.code(), Some(1));
                let refresh_report = json_stdout(&refresh_doctor);
                assert_eq!(
                    refresh_report["diagnostics"][0]["code"],
                    "breg.external-refresh.view-missing",
                    "{refresh_report}"
                );
            });
            admin
                .batch_execute(&format!("DROP DATABASE {database} WITH (FORCE)"))
                .await
                .unwrap();
            admin
                .batch_execute(&format!("DROP ROLE {role}"))
                .await
                .unwrap();
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        }
        drop(admin);
        owner.await.unwrap().unwrap();
    });
}
