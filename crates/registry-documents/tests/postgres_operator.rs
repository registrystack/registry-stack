// SPDX-License-Identifier: Apache-2.0

//! Database-backed operator tests: `documentsctl plan` previews and
//! `documentsctl apply` applies the schema and records the package in the
//! activation ledger, `serve` refuses a database the ledger does not name
//! this package and deployment active in, `documentsctl status` reads the
//! ledger, and `documentsctl verification replay` returns a dead-lettered
//! content verification job to pending and refuses every other job.
//!
//! Every test runs in its own schema inside the database named by
//! `DOCUMENTS_TEST_DATABASE_URL`; without it every test fails on the spot.

mod support;

use std::sync::Arc;

use axum::body::Body;
use registry_documents::activation::{ActivationChange, ActivationError, ApplyRequest};
use registry_documents::config::RuntimeConfig;
use registry_documents::runtime::{
    activation_plan, activation_status, apply_activation, dead_lettered_verifications, prepare,
    prepare_with_verifier, replay_verification, Prepared, RuntimeError,
};
use registry_documents::verification::{ReplayRefusal, MAXIMUM_ATTEMPTS};
use registry_platform_activation::{DatabaseIdCheck, PlanKind, RoleMode};
use support::{
    database_url, pdf, reservation, Api, Deployment, FakeVerifier, APP, APPROVE, CITIZEN,
    DATABASE_STORAGE, DISABLED_VERIFIER, STARTER_PROJECT, UNAVAILABLE,
};
use url::Url;
use uuid::Uuid;

fn config(deployment: &Deployment) -> RuntimeConfig {
    RuntimeConfig::load(&deployment.runtime).expect("the test runtime document loads")
}

/// The relations in the deployment's isolated schema.
async fn relations(deployment: &Deployment) -> i64 {
    deployment
        .scalar(&format!(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = '{}'",
            deployment.schema
        ))
        .await
}

/// Point the runtime document at a package of `project` written under
/// `name`, as an operator does when deploying a changed package.
fn redeploy(deployment: &Deployment, name: &str, project: &str) {
    let package = deployment.path().join(name);
    let files = std::collections::BTreeMap::from([(
        registry_documents::package::PROJECT_FILE.to_owned(),
        project.as_bytes().to_vec(),
    )]);
    registry_platform_config::write_package(
        &package,
        &files,
        None,
        &registry_documents::package::package_limits(),
        registry_documents::package::PACKAGE_COMMAND,
    )
    .unwrap();
    rewrite_runtime(
        deployment,
        &format!("root: {}", deployment.path().join("package").display()),
        &format!("root: {}", package.display()),
    );
}

fn rewrite_runtime(deployment: &Deployment, from: &str, to: &str) {
    let text = std::fs::read_to_string(&deployment.runtime).unwrap();
    assert!(text.contains(from), "the runtime document names {from}");
    std::fs::write(&deployment.runtime, text.replace(from, to)).unwrap();
}

#[tokio::test]
async fn a_fresh_database_is_refused_by_serve_until_the_package_is_applied() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    let error = prepare(&deployment.runtime)
        .await
        .expect_err("an unactivated database is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::NotActivated)
        ),
        "{error}"
    );
    assert!(
        error.to_string().contains("documentsctl apply"),
        "the refusal names the remedy: {error}"
    );

    let applied = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .expect("the package applies");
    assert!(applied.recorded);
    assert_eq!(applied.schema_versions_applied, vec![100]);
    assert_eq!(applied.activation.plan_kind, PlanKind::Initial);
    assert_eq!(applied.activation.role_mode, RoleMode::Single);
    prepare(&deployment.runtime)
        .await
        .expect("the activated database serves");
}

#[tokio::test]
async fn plan_reports_the_change_and_writes_nothing() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    assert_eq!(relations(&deployment).await, 0);
    let plan = activation_plan(&config(&deployment))
        .await
        .expect("a fresh database plans");
    assert_eq!(plan.change, ActivationChange::Activate);
    assert_eq!(plan.plan_kind, PlanKind::Initial);
    assert_eq!(plan.active_digest, None);
    assert_eq!(plan.pending_schema_versions, vec![100]);
    assert_eq!(plan.database_id, DatabaseIdCheck::NotRecorded);
    assert!(plan.refusals.is_empty(), "{:?}", plan.refusals);
    assert!(plan.package_digest.starts_with("sha256:"));
    assert_eq!(relations(&deployment).await, 0, "plan created nothing");

    let applied = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .unwrap();
    let before = relations(&deployment).await;
    let ledger_before: i64 = deployment
        .scalar("SELECT count(*) FROM documents_activations")
        .await;
    let plan = activation_plan(&config(&deployment)).await.unwrap();
    assert_eq!(plan.change, ActivationChange::None);
    assert_eq!(plan.plan_kind, PlanKind::Successor);
    assert_eq!(
        plan.active_digest.as_deref(),
        Some(applied.activation.package_digest.as_str())
    );
    assert!(plan.pending_schema_versions.is_empty());
    assert_eq!(plan.database_id, DatabaseIdCheck::Matches);
    assert_eq!(relations(&deployment).await, before);
    let ledger_after: i64 = deployment
        .scalar("SELECT count(*) FROM documents_activations")
        .await;
    assert_eq!(ledger_after, ledger_before, "plan recorded nothing");
}

#[tokio::test]
async fn apply_is_idempotent_for_one_package_and_records_a_changed_one() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    let request = ApplyRequest {
        operator_reference: Some("CHG-1042".to_owned()),
        backup_references: vec!["backup-2026-10-22".to_owned()],
    };
    let first = apply_activation(&config(&deployment), &request)
        .await
        .unwrap();
    assert!(first.recorded);
    let hash = first
        .activation
        .operator_reference_hash
        .clone()
        .expect("the operator reference is recorded as a keyed hash");
    assert!(!hash.contains("CHG-1042"));
    assert_eq!(
        first.activation.backup_references,
        vec!["backup-2026-10-22".to_owned()]
    );

    let again = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .unwrap();
    assert!(!again.recorded, "the same package records nothing");
    assert!(again.schema_versions_applied.is_empty());
    assert_eq!(
        again.activation.activation_id,
        first.activation.activation_id
    );
    let entries: i64 = deployment
        .scalar("SELECT count(*) FROM documents_activations")
        .await;
    assert_eq!(entries, 1);

    // A changed package is refused by serve until it is applied.
    redeploy(
        &deployment,
        "package-2",
        &format!("{STARTER_PROJECT}\n# A reviewed change.\n"),
    );
    let error = prepare(&deployment.runtime)
        .await
        .expect_err("the changed package is not active");
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::PackageNotActive)
        ),
        "{error}"
    );
    let plan = activation_plan(&config(&deployment)).await.unwrap();
    assert_eq!(plan.change, ActivationChange::Activate);
    assert_eq!(plan.plan_kind, PlanKind::Successor);

    let second = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .unwrap();
    assert!(second.recorded);
    assert_eq!(second.activation.plan_kind, PlanKind::Successor);
    assert_eq!(
        second.activation.predecessor_package_digest.as_deref(),
        Some(first.activation.package_digest.as_str())
    );
    assert_ne!(
        second.activation.package_digest,
        first.activation.package_digest
    );
    let entries: i64 = deployment
        .scalar("SELECT count(*) FROM documents_activations")
        .await;
    assert_eq!(entries, 2);
    prepare(&deployment.runtime)
        .await
        .expect("the applied successor serves");
}

#[tokio::test]
async fn status_reports_the_active_package_and_its_history() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    let status = activation_status(&config(&deployment))
        .await
        .expect("a fresh database has a status");
    assert!(status.active.is_none());
    assert!(status.history.is_empty());
    assert_eq!(status.schema_version, None);

    let first = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .unwrap();
    redeploy(
        &deployment,
        "package-2",
        &format!("{STARTER_PROJECT}\n# A reviewed change.\n"),
    );
    let second = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .unwrap();
    let status = activation_status(&config(&deployment)).await.unwrap();
    let active = status.active.expect("an active package");
    assert_eq!(active.activation_id, second.activation.activation_id);
    assert_eq!(active.package_digest, second.activation.package_digest);
    assert_eq!(active.database_id, "registry-documents-test");
    assert_eq!(status.schema_version, Some(100));
    assert_eq!(
        status
            .history
            .iter()
            .map(|entry| entry.activation_id)
            .collect::<Vec<_>>(),
        vec![
            first.activation.activation_id,
            second.activation.activation_id
        ]
    );
    assert_eq!(status.runtime_role_mode, Some(RoleMode::Single));
}

#[tokio::test]
async fn a_database_recorded_for_another_deployment_is_refused() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .unwrap();
    rewrite_runtime(
        &deployment,
        "databaseId: registry-documents-test",
        "databaseId: registry-documents-other",
    );
    let error = prepare(&deployment.runtime)
        .await
        .expect_err("another deployment's database is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::DatabaseIdMismatch)
        ),
        "{error}"
    );
    let plan = activation_plan(&config(&deployment)).await.unwrap();
    assert_eq!(plan.database_id, DatabaseIdCheck::Differs);
    assert!(plan
        .refusals
        .iter()
        .any(|refusal| refusal.code == "documentsctl.activation.database-id-mismatch"));
    let error = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .expect_err("apply refuses another deployment's database");
    assert!(
        matches!(
            &error,
            RuntimeError::Activation(ActivationError::Refused(refusals))
                if refusals.iter().any(|refusal| refusal.code == "documentsctl.activation.database-id-mismatch")
        ),
        "{error}"
    );
    let entries: i64 = deployment
        .scalar("SELECT count(*) FROM documents_activations")
        .await;
    assert_eq!(entries, 1);
}

#[tokio::test]
async fn invalid_operator_references_are_refused_before_anything_is_written() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    for request in [
        ApplyRequest {
            operator_reference: Some(String::new()),
            backup_references: Vec::new(),
        },
        ApplyRequest {
            operator_reference: Some("line\nbreak".to_owned()),
            backup_references: Vec::new(),
        },
        ApplyRequest {
            operator_reference: None,
            backup_references: vec!["backup".to_owned(); 17],
        },
    ] {
        let error = apply_activation(&config(&deployment), &request)
            .await
            .expect_err("the reference is refused");
        assert!(
            matches!(
                &error,
                RuntimeError::Activation(ActivationError::Refused(refusals))
                    if refusals[0].code == "documentsctl.activation.invalid-reference"
            ),
            "{error}"
        );
    }
    assert_eq!(relations(&deployment).await, 0);
}

/// A login role with no authority over the deployment's schema, and the
/// URL that reaches the schema as it.
async fn limited_role(deployment: &Deployment) -> String {
    let role = format!("p1doc_runtime_{}", Uuid::new_v4().simple());
    deployment
        .admin
        .batch_execute(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD 'documents-test' NOSUPERUSER NOCREATEDB NOCREATEROLE"
        ))
        .await
        .unwrap();
    let mut url = Url::parse(&database_url()).unwrap();
    url.set_username(&role).unwrap();
    url.set_password(Some("documents-test")).unwrap();
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={}", deployment.schema));
    url.to_string()
}

#[tokio::test]
async fn apply_requires_the_migration_credential() {
    let mut deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    let limited = limited_role(&deployment).await;
    deployment.secret("runtime-database-url", &limited);

    // The runtime credential cannot apply the schema: with it named as the
    // migration credential too, apply fails and records nothing.
    deployment.secret("migration-database-url", &limited);
    let error = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .expect_err("the runtime credential cannot apply");
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::Store(_))
                | RuntimeError::Activation(ActivationError::Refused(_))
        ),
        "{error}"
    );
    assert_eq!(relations(&deployment).await, 0);

    // With the migration credential, apply splits the roles: the runtime
    // role is granted exactly what serving needs, and serve starts.
    let scoped = {
        let base = database_url();
        let separator = if base.contains('?') { '&' } else { '?' };
        format!(
            "{base}{separator}options=-csearch_path%3D{}",
            deployment.schema
        )
    };
    deployment.secret("migration-database-url", &scoped);
    let applied = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .expect("the migration credential applies");
    assert!(applied.recorded);
    assert_eq!(applied.activation.role_mode, RoleMode::Split);
    let status = activation_status(&config(&deployment)).await.unwrap();
    assert_eq!(status.runtime_role_mode, Some(RoleMode::Split));
    assert_eq!(status.grants_current, Some(true));
    prepare(&deployment.runtime)
        .await
        .expect("the runtime role serves the activated database");
}

async fn start(deployment: &Deployment, verifier: &Arc<FakeVerifier>) -> (Prepared, Api) {
    let prepared = prepare_with_verifier(&deployment.runtime, verifier.clone())
        .await
        .expect("the runtime prepares");
    let api = Api::new(&prepared);
    (prepared, api)
}

/// Upload one document whose verification job the worker dead-letters.
async fn dead_lettered(deployment: &Deployment, prepared: &Prepared, api: &Api) -> Uuid {
    let content = pdf(256, 21);
    let reserved = api
        .reserve(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            &content,
            "application/pdf",
        )
        .await;
    let (_document, version, path) = reservation(&reserved);
    let put = api
        .put(APP, &path, "application/pdf", Body::from(content))
        .await;
    assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    deployment
        .execute(&format!(
            "UPDATE documents_verification_jobs
                SET attempt = {}, next_attempt_at = now()",
            MAXIMUM_ATTEMPTS - 1
        ))
        .await;
    assert_eq!(prepared.verify_due().await, 1);
    let state: String = deployment
        .scalar("SELECT state FROM documents_verification_jobs")
        .await;
    assert_eq!(state, "dead-lettered");
    version.parse().unwrap()
}

#[tokio::test]
async fn replay_returns_a_dead_lettered_verification_to_pending() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let version = dead_lettered(&deployment, &prepared, &api).await;

    let listed = dead_lettered_verifications(&config(&deployment), 50)
        .await
        .expect("the dead letters list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].version_id, version);
    assert_eq!(listed[0].generation, 1);
    assert_eq!(listed[0].attempt, MAXIMUM_ATTEMPTS);

    // A stale generation is refused and changes nothing.
    let error = replay_verification(&config(&deployment), version, 2)
        .await
        .expect_err("a stale generation is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Replay(ReplayRefusal::StaleGeneration { current: 1 })
        ),
        "{error}"
    );

    let replayed = replay_verification(&config(&deployment), version, 1)
        .await
        .expect("the dead letter replays");
    assert_eq!(replayed.version_id, version);
    assert_eq!(replayed.generation, 2);
    let pending: bool = deployment
        .scalar(
            "SELECT state = 'pending' AND generation = 2 AND attempt = 0
               FROM documents_verification_jobs",
        )
        .await;
    assert!(pending, "the job is pending again under a new generation");
    let (verification, eligibility): (String, String) = (
        deployment
            .scalar("SELECT verification_state FROM documents_versions")
            .await,
        deployment
            .scalar("SELECT eligibility FROM documents_versions")
            .await,
    );
    assert_eq!(
        (verification.as_str(), eligibility.as_str()),
        ("pending", "suspended"),
        "a replay neither approves nor releases"
    );
    assert!(dead_lettered_verifications(&config(&deployment), 50)
        .await
        .unwrap()
        .is_empty());

    // The replay is audited in the operator's companion journal.
    let journal = std::fs::read_to_string(deployment.path().join("audit.documentsctl.ndjson"))
        .expect("a documentsctl companion audit journal");
    assert!(journal.contains("\"transition\":\"replayed\""), "{journal}");
    assert!(journal.contains(&version.to_string()));

    // The job is no longer dead-lettered, so a second replay is refused.
    let error = replay_verification(&config(&deployment), version, 2)
        .await
        .expect_err("a pending job is not replayed");
    assert!(
        matches!(
            &error,
            RuntimeError::Replay(ReplayRefusal::NotDeadLettered { state }) if state == "pending"
        ),
        "{error}"
    );

    // The replayed job is verified like any other.
    verifier.answer(APPROVE);
    assert_eq!(prepared.verify_due().await, 1);
    let eligibility: String = deployment
        .scalar("SELECT eligibility FROM documents_versions")
        .await;
    assert_eq!(eligibility, "releasable");
}

#[tokio::test]
async fn replay_refuses_an_unknown_version_and_an_unactivated_database() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    let error = replay_verification(&config(&deployment), Uuid::new_v4(), 1)
        .await
        .expect_err("an unactivated database is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::NotActivated)
        ),
        "{error}"
    );
    let error = dead_lettered_verifications(&config(&deployment), 50)
        .await
        .expect_err("an unactivated database is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::NotActivated)
        ),
        "{error}"
    );

    deployment.migrate().await;
    let error = replay_verification(&config(&deployment), Uuid::new_v4(), 1)
        .await
        .expect_err("an unknown version is refused");
    assert!(
        matches!(error, RuntimeError::Replay(ReplayRefusal::NotFound)),
        "{error}"
    );
}
