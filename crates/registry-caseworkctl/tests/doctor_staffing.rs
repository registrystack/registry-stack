// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]
#![allow(
    clippy::disallowed_methods,
    reason = "test edits only its synthetic authored project"
)]
use serde_json::{json, Value};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
use tokio_postgres::NoTls;
use uuid::Uuid;

fn ctl(args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_caseworkctl"))
        .args(["--format", "json"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "synthetic operator command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn secret(path: &Path, value: &str) {
    fs::write(path, value).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn doctor_warns_for_one_distinct_member_and_clears_after_a_second_joins() {
    let base = std::env::var("CASEWORK_TEST_DATABASE_URL")
        .expect("an explicitly disposable Casework operator database is required");
    let schema = format!("doctor_staffing_{}", Uuid::new_v4().simple());
    let (admin, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let project = root_path.join("project");
    ctl(&[
        "init",
        project.to_str().unwrap(),
        "--template",
        "standalone-decision",
    ]);
    let policy_path = project.join("casework.yaml");
    let mut policy: Value = serde_norway::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    policy["teams"] = json!({"review-team":{"label":"Review team","serves":["decisions"],
        "memberProfiles":["staff"],"supervisorProfiles":["supervisor"]}});
    policy["reviewPolicies"]["decision"]["purpose"] = json!("approval");
    policy["reviewPolicies"]["decision"]["stages"][0]["requiredApprovals"] = json!(2);
    policy["reviewPolicies"]["decision"]["outcomes"] = json!({"approved":{
        "label":"Approve","settlement":"approved","reasonRequired":false,"publicReason":"optional"}});
    fs::write(&policy_path, serde_norway::to_string(&policy).unwrap()).unwrap();
    let package = root_path.join("package");
    ctl(&[
        "package",
        project.to_str().unwrap(),
        "--output",
        package.to_str().unwrap(),
    ]);
    let secrets = root_path.join("secrets");
    fs::create_dir(&secrets).unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
    secret(&secrets.join("database"), &scoped);
    secret(
        &secrets.join("audit-key"),
        "doctor-staffing-audit-key-canary",
    );
    let config = json!({
        "apiVersion":registry_casework::RUNTIME_CONFIG_API_VERSION,"kind":registry_casework::RUNTIME_CONFIG_KIND,
        "identity":{"databaseId":"doctor-staffing"},"package":{"root":package},
        "listener":{"bind":"127.0.0.1:8100","tlsTermination":"development-loopback","networkExposure":"private-address"},
        "secretProviders":{"file":{"root":secrets}},
        "database":{"runtimeUrlRef":"secret:file/database","migrationUrlRef":"secret:file/database","testOnlyPlaintext":true},
        "authentication":{"oidc":{"issuer":"https://identity.example.test","audience":"urn:example:casework",
            "allowedClients":"unrestricted","scopeClaim":"scope","humanIdentity":{"claim":"registry_actor_kind","value":"human"}}},
        "audit":{"path":root_path.join("audit.ndjson"),"hashKeyRef":"secret:file/audit-key"}
    });
    let runtime = root_path.join("runtime.yaml");
    fs::write(&runtime, serde_norway::to_string(&config).unwrap()).unwrap();
    let initial = ctl(&["doctor", "--runtime-config", runtime.to_str().unwrap()]);
    assert_eq!(
        initial["ok"], true,
        "doctor still preflights an empty deployment"
    );
    ctl(&["apply", "--runtime-config", runtime.to_str().unwrap()]);
    let (db, connection) = tokio_postgres::connect(&scoped, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    db.batch_execute("INSERT INTO casework_teams(team_id,revision) VALUES('review-team',1) ON CONFLICT DO NOTHING;
        INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('decisions','review-team',1) ON CONFLICT DO NOTHING;
        INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES
        ('review-team','https://identity.example.test','staff-one-canary','staff');").await.unwrap();
    let warning = ctl(&["doctor", "--runtime-config", runtime.to_str().unwrap()]);
    let text = warning.to_string();
    assert!(
        text.contains("casework.staffing.insufficient-distinct-approvers"),
        "doctor must name the distinct-reviewer shortfall"
    );
    for private in [
        "staff-one-canary",
        "doctor-staffing-audit-key-canary",
        &scoped,
    ] {
        assert!(
            !text.contains(private),
            "doctor warning must not contain identities or secrets"
        );
    }
    db.execute(
        "INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind)
        VALUES('review-team','https://identity.example.test','staff-two-canary','staff')",
        &[],
    )
    .await
    .unwrap();
    let ready = ctl(&["doctor", "--runtime-config", runtime.to_str().unwrap()]);
    assert!(!ready
        .to_string()
        .contains("casework.staffing.insufficient-distinct-approvers"));
    assert!(!ready.to_string().contains("staff-two-canary"));
}
