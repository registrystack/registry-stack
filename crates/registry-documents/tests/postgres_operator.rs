// SPDX-License-Identifier: Apache-2.0

//! Database-backed operator tests: `documentsctl plan` previews and
//! `documentsctl apply` applies the schema and records the package in the
//! activation ledger, `serve` refuses a database the ledger does not name
//! this package and deployment active in, `documentsctl status` reads the
//! ledger, and `documentsctl verification replay` and `documentsctl
//! erasure replay` return a dead-lettered content verification or erasure
//! job to pending and refuse every other job.
//!
//! Every test runs in its own schema inside the database named by
//! `DOCUMENTS_TEST_DATABASE_URL`; without it every test fails on the spot.

mod support;

use std::sync::Arc;

use axum::body::Body;
use registry_documents::activation::{ActivationChange, ActivationError, ApplyRequest};
use registry_documents::audit::DocumentsAudit;
use registry_documents::config::RuntimeConfig;
use registry_documents::erasure::{ErasureStatus, ErasureStore};
use registry_documents::runtime::{
    activation_plan, activation_status, apply_activation, dead_lettered_erasures,
    dead_lettered_verifications, erasure_report, prepare, prepare_with_verifier, replay_erasure,
    replay_verification, Prepared, RuntimeError,
};
use registry_documents::store::StoreError;
use registry_documents::verification::{
    replay, Graces, ReplayError, ReplayFailure, ReplayRefusal, VerificationStore, MAXIMUM_ATTEMPTS,
};
use registry_documents_core::ProblemCode;
use registry_platform_activation::{DatabaseIdCheck, PlanKind, RoleMode};
use registry_platform_audit::{AuditProfile, AuditWriter};
use support::{
    database_url, pdf, reservation, Api, Deployment, FakeVerifier, APP, APPROVE, CITIZEN,
    DATABASE_STORAGE, DISABLED_VERIFIER, READER, STARTER_PROJECT, UNAVAILABLE,
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
/// URL that reaches the schema as it. Roles are cluster-wide, so each test
/// names its own and drops it with [`drop_role`] before it ends.
async fn limited_role(deployment: &Deployment) -> (String, String) {
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
    (role, url.to_string())
}

/// Drop `role` and every privilege it was granted in this database.
async fn drop_role(deployment: &Deployment, role: &str) {
    deployment
        .admin
        .batch_execute(&format!("DROP OWNED BY {role}; DROP ROLE {role}"))
        .await
        .unwrap();
}

/// The URL that reaches the deployment's schema as the migration role.
fn migration_url(deployment: &Deployment) -> String {
    let base = database_url();
    let separator = if base.contains('?') { '&' } else { '?' };
    format!(
        "{base}{separator}options=-csearch_path%3D{}",
        deployment.schema
    )
}

/// A deployment whose runtime role is split from its migration role by
/// apply, and the runtime role's name.
async fn split_deployment() -> (Deployment, String) {
    let mut deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    let (role, limited) = limited_role(&deployment).await;
    deployment.secret("runtime-database-url", &limited);
    deployment.secret("migration-database-url", &migration_url(&deployment));
    let applied = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .expect("the migration credential applies");
    assert_eq!(applied.activation.role_mode, RoleMode::Split);
    prepare(&deployment.runtime)
        .await
        .expect("the runtime role serves the activated database");
    (deployment, role)
}

#[tokio::test]
async fn apply_requires_the_migration_credential() {
    let mut deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    let (role, limited) = limited_role(&deployment).await;
    deployment.secret("runtime-database-url", &limited);

    // The runtime credential cannot apply the schema: with it named as the
    // migration credential too, apply fails and records nothing. The role
    // has no authority over the schema, so PostgreSQL finds no schema on
    // its search path to create the first table in.
    deployment.secret("migration-database-url", &limited);
    let error = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .expect_err("the runtime credential cannot apply");
    assert!(
        matches!(
            &error,
            RuntimeError::Activation(ActivationError::Store(StoreError::Query(query)))
                if query.code() == Some(&tokio_postgres::error::SqlState::INVALID_SCHEMA_NAME)
        ),
        "{error}"
    );
    assert_eq!(relations(&deployment).await, 0);
    // The journal answers the failed apply rather than leaving its request
    // open.
    let journal = std::fs::read_to_string(deployment.path().join("audit.documentsctl.ndjson"))
        .expect("a documentsctl companion audit journal");
    assert!(journal.contains("\"outcome\":\"failed\""), "{journal}");
    assert!(!journal.contains("\"outcome\":\"unfinished\""), "{journal}");

    // With the migration credential, apply splits the roles: the runtime
    // role is granted exactly what serving needs, and serve starts.
    deployment.secret("migration-database-url", &migration_url(&deployment));
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
    drop_role(&deployment, &role).await;
}

#[tokio::test]
async fn serve_refuses_a_runtime_role_that_gained_authority_over_the_schema() {
    let (deployment, role) = split_deployment().await;
    deployment
        .execute(&format!(
            "GRANT CREATE ON SCHEMA {} TO {role}",
            deployment.schema
        ))
        .await;
    let error = prepare(&deployment.runtime)
        .await
        .expect_err("a runtime role with schema authority is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::RoleModeWeakened)
        ),
        "{error}"
    );
    drop_role(&deployment, &role).await;
}

#[tokio::test]
async fn serve_refuses_a_runtime_role_that_lost_a_grant() {
    let (deployment, role) = split_deployment().await;
    deployment
        .execute(&format!("REVOKE SELECT ON documents_versions FROM {role}"))
        .await;
    let error = prepare(&deployment.runtime)
        .await
        .expect_err("a runtime role missing a grant is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::GrantsStale)
        ),
        "{error}"
    );
    drop_role(&deployment, &role).await;
}

/// A runtime role that lost USAGE on the schema the package was applied in
/// sees no ledger through its search path. Startup is refused as a missing
/// grant, never as a database nobody activated, so the operator restores
/// the role's grants rather than looking for an apply that never ran.
#[tokio::test]
async fn serve_refuses_a_runtime_role_that_lost_usage_on_the_schema_as_a_grant_problem() {
    let (deployment, role) = split_deployment().await;
    deployment
        .execute(&format!(
            "REVOKE USAGE ON SCHEMA {} FROM {role}",
            deployment.schema
        ))
        .await;
    let error = prepare(&deployment.runtime)
        .await
        .expect_err("a runtime role without schema usage is refused");
    let message = error.to_string();
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::LedgerUnreadable)
        ),
        "{message}"
    );
    assert!(
        message.contains("restore the runtime role's grants"),
        "{message}"
    );
    assert!(
        message.contains("(documentsctl.activation.ledger-unreadable)"),
        "{message}"
    );
    drop_role(&deployment, &role).await;
}

/// DOCUMENTS-DEC-17: the ledger is read first, so an activated database
/// whose schema has moved past this release is refused as a schema
/// mismatch, never as unactivated.
#[tokio::test]
async fn serve_refuses_an_activated_database_with_a_newer_schema_version() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    deployment
        .execute(
            "INSERT INTO documents_schema_migrations(version, applied_at)
             SELECT max(version) + 1, now() FROM documents_schema_migrations",
        )
        .await;
    let error = prepare(&deployment.runtime)
        .await
        .expect_err("a newer schema version is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::Store(StoreError::SchemaVersion))
        ),
        "{error}"
    );
}

async fn start(deployment: &Deployment, verifier: &Arc<FakeVerifier>) -> (Prepared, Api) {
    let prepared = prepare_with_verifier(&deployment.runtime, verifier.clone())
        .await
        .expect("the runtime prepares");
    let api = Api::new(&prepared);
    (prepared, api)
}

async fn ready_document(prepared: &Prepared, api: &Api, content: &[u8]) -> (String, String) {
    let (document, version, path) = reservation(
        &api.reserve(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            content,
            "application/pdf",
        )
        .await,
    );
    assert_eq!(
        api.put(APP, &path, "application/pdf", Body::from(content.to_vec()))
            .await
            .status,
        200
    );
    assert_eq!(prepared.verify_due().await, 1);
    (document, version)
}

fn successor(deployment: &Deployment) {
    let changed =
        STARTER_PROJECT.replace("recipientProfiles: [reader]", "recipientProfiles: [staff]");
    assert_ne!(changed, STARTER_PROJECT);
    redeploy(deployment, "successor", &changed);
}

/// Every protected route refuses a stale or unreadable package identity,
/// including in-memory policy discovery and requests that would mutate.
async fn assert_protected_routes_unavailable(
    api: &Api,
    document: &str,
    version: &str,
    upload: &str,
    grant: &str,
) {
    for path in [
        "/v1/document-policies".to_owned(),
        "/v1/documents".to_owned(),
        format!("/v1/documents/{document}"),
        format!("/v1/documents/{document}/versions/{version}/content"),
        format!("/v1/documents/{document}/grants"),
        "/v1/document-grants".to_owned(),
    ] {
        api.get(CITIZEN, &path)
            .await
            .assert_problem(ProblemCode::ServiceUnavailable);
    }
    api.download(READER, document, version)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    api.reserve(
        APP,
        "citizen-delivery",
        CITIZEN.subject,
        b"x",
        "application/pdf",
    )
    .await
    .assert_problem(ProblemCode::ServiceUnavailable);
    api.put(APP, upload, "application/pdf", Body::from("x"))
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    api.grant(CITIZEN, document, version, READER.subject, None)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    api.revoke(CITIZEN, grant)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    api.erase(CITIZEN, document)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
}

#[tokio::test]
async fn successor_activation_fences_every_old_route_and_preserves_an_admitted_download() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(512, 77);
    let (document, version) = ready_document(&prepared, &api, &content).await;
    let grant = api
        .grant(CITIZEN, &document, &version, READER.subject, None)
        .await;
    assert_eq!(grant.status, 201);
    let grant = grant.json()["id"].as_str().unwrap().to_owned();
    let (_, _, upload) = reservation(
        &api.reserve(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            b"x",
            "application/pdf",
        )
        .await,
    );
    let admitted = api
        .respond(
            support::request(
                READER,
                axum::http::Method::GET,
                &format!("/v1/documents/{document}/versions/{version}/content"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    assert_eq!(admitted.status(), 200);
    successor(&deployment);
    deployment.migrate().await;
    api.get(CITIZEN, "/ready")
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    assert_eq!(api.get(CITIZEN, "/health").await.status, 200);
    assert_protected_routes_unavailable(&api, &document, &version, &upload, &grant).await;
    assert_eq!(
        axum::body::to_bytes(admitted.into_body(), usize::MAX)
            .await
            .unwrap()
            .as_ref(),
        content
    );
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_documents")
            .await,
        2
    );
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_grants WHERE revoked_at IS NULL")
            .await,
        1
    );
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_versions WHERE erasure_state <> 'none'")
            .await,
        0
    );
    // Drop both holders of the old audit writer before starting its successor.
    drop(api);
    drop(prepared);
    let (_prepared, api) = start(&deployment, &verifier).await;
    assert_eq!(api.get(CITIZEN, "/ready").await.status, 200);
    api.download(READER, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    assert_eq!(
        api.download(CITIZEN, &document, &version).await.body,
        content
    );
}

#[tokio::test]
async fn a_running_runtime_fails_closed_when_activation_access_is_lost() {
    let (deployment, role) = split_deployment().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = ready_document(&prepared, &api, &pdf(512, 78)).await;
    let grant = api
        .grant(CITIZEN, &document, &version, READER.subject, None)
        .await
        .json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, _, upload) = reservation(
        &api.reserve(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            b"x",
            "application/pdf",
        )
        .await,
    );
    assert_eq!(
        api.put(APP, &upload, "application/pdf", Body::from("x"))
            .await
            .status,
        200
    );
    for revoke in [
        format!("REVOKE SELECT ON documents_activations FROM {role}"),
        format!("REVOKE USAGE ON SCHEMA {} FROM {role}", deployment.schema),
    ] {
        deployment.execute(&revoke).await;
        assert_protected_routes_unavailable(&api, &document, &version, &upload, &grant).await;
        assert_eq!(prepared.verify_due().await, 0);
        assert!(prepared.cleanup_pass().await.is_err());
        deployment.migrate().await;
        assert_eq!(api.read(CITIZEN, &document).await.status, 200);
    }
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_documents")
            .await,
        2
    );
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_grants WHERE revoked_at IS NULL")
            .await,
        1
    );
    drop(api);
    drop(prepared);
    drop_role(&deployment, &role).await;
}

/// A request that authenticated before activation still rechecks authority
/// inside its finalizing transaction. Upload bytes themselves hold no lock.
#[tokio::test]
async fn an_upload_admitted_before_activation_cannot_finalize_under_the_old_package() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let content = pdf(512, 79);
    let (_, _, path) = reservation(
        &api.reserve(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            &content,
            "application/pdf",
        )
        .await,
    );
    let (entered, entering) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let stream = futures::stream::once(async move {
        entered.send(()).unwrap();
        released.await.unwrap();
        Ok::<_, std::io::Error>(axum::body::Bytes::from(content))
    });
    let uploading = tokio::spawn(async move {
        api.put(APP, &path, "application/pdf", Body::from_stream(stream))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entering)
        .await
        .unwrap()
        .unwrap();
    successor(&deployment);
    deployment.migrate().await;
    release.send(()).unwrap();
    uploading
        .await
        .unwrap()
        .assert_problem(ProblemCode::ServiceUnavailable);
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_contents")
            .await,
        0
    );
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_verification_jobs")
            .await,
        0
    );
    assert_eq!(
        deployment
            .scalar::<String>("SELECT upload_state FROM documents_versions")
            .await,
        "reserved"
    );
}

/// Observe an actual database wait rather than using a sleep to guess that
/// the concurrent operation reached its transaction boundary.
async fn wait_for_database(deployment: &Deployment, query: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if deployment.scalar::<bool>(query).await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the database operation reaches the expected wait");
}

#[tokio::test]
async fn activation_waits_for_a_mutation_that_already_holds_package_authority() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = ready_document(&prepared, &api, &pdf(512, 80)).await;
    let grant = api
        .grant(CITIZEN, &document, &version, READER.subject, None)
        .await
        .json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    deployment
        .execute(&format!(
            "BEGIN; SELECT grant_id FROM documents_grants WHERE grant_id = '{grant}' FOR UPDATE"
        ))
        .await;
    let revoke_api = api.clone();
    let revoking = tokio::spawn(async move { revoke_api.revoke(CITIZEN, &grant).await });
    wait_for_database(&deployment, "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pg_backend_pid() = ANY(pg_blocking_pids(pid)))").await;
    successor(&deployment);
    let applying_config = config(&deployment);
    let applying =
        tokio::spawn(
            async move { apply_activation(&applying_config, &ApplyRequest::default()).await },
        );
    wait_for_database(&deployment,
        "SELECT EXISTS (SELECT 1 FROM pg_locks AS exclusive JOIN pg_locks AS shared
           ON (exclusive.database, exclusive.classid, exclusive.objid, exclusive.objsubid)
            = (shared.database, shared.classid, shared.objid, shared.objsubid)
          WHERE exclusive.locktype = 'advisory' AND exclusive.mode = 'ExclusiveLock'
            AND NOT exclusive.granted AND shared.mode = 'ShareLock' AND shared.granted
            AND shared.pid IN (SELECT pid FROM pg_locks WHERE pg_backend_pid() = ANY(pg_blocking_pids(pid))))"
    ).await;
    assert!(
        !applying.is_finished(),
        "activation waits for the admitted mutation"
    );
    let refused = tokio::time::timeout(std::time::Duration::from_secs(7), applying)
        .await
        .expect("apply bounds the lock wait")
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(refused, RuntimeError::Activation(ActivationError::Store(StoreError::Query(ref error)))
        if error.code() == Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)),
        "{refused}"
    );
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_activations")
            .await,
        1
    );
    let applying_config = config(&deployment);
    let applying =
        tokio::spawn(
            async move { apply_activation(&applying_config, &ApplyRequest::default()).await },
        );
    deployment.execute("COMMIT").await;
    assert_eq!(revoking.await.unwrap().status, 200);
    assert!(applying.await.unwrap().unwrap().recorded);
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_grants WHERE revoked_at IS NOT NULL")
            .await,
        1
    );
    api.erase(CITIZEN, &document)
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
}

#[tokio::test]
async fn runtime_and_apply_refuse_an_activation_ledger_in_a_later_search_path_schema() {
    let mut deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let shadow = format!("documents_shadow_{}", Uuid::new_v4().simple());
    deployment.execute(&format!("CREATE SCHEMA {shadow}")).await;
    let mut url = Url::parse(&database_url()).unwrap();
    url.query_pairs_mut().append_pair(
        "options",
        &format!("-csearch_path={shadow},{}", deployment.schema),
    );
    deployment.secret("runtime-database-url", url.as_str());
    let error = prepare(&deployment.runtime).await.unwrap_err();
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::Store(StoreError::ActivationSchemaMismatch))
        ),
        "{error}"
    );
    deployment.secret("migration-database-url", url.as_str());
    let error = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::Store(StoreError::ActivationSchemaMismatch))
        ),
        "{error}"
    );
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_activations")
            .await,
        1
    );
    assert_eq!(
        deployment
            .scalar::<i64>(&format!(
                "SELECT count(*) FROM pg_class WHERE relnamespace = '{shadow}'::regnamespace"
            ))
            .await,
        0
    );
}

#[tokio::test]
async fn a_running_runtime_refuses_a_new_schema_before_its_activation_ledger() {
    let mut deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let shadow = format!("documents_shadow_{}", Uuid::new_v4().simple());
    let mut url = Url::parse(&database_url()).unwrap();
    url.query_pairs_mut().append_pair(
        "options",
        &format!("-csearch_path={shadow},{}", deployment.schema),
    );
    deployment.secret("runtime-database-url", url.as_str());
    let prepared = prepare(&deployment.runtime).await.unwrap();
    let api = Api::new(&prepared);
    assert_eq!(api.get(APP, "/v1/document-policies").await.status, 200);
    deployment.execute(&format!("CREATE SCHEMA {shadow}")).await;
    api.get(APP, "/v1/document-policies")
        .await
        .assert_problem(ProblemCode::ServiceUnavailable);
    api.reserve(
        APP,
        "citizen-delivery",
        CITIZEN.subject,
        b"x",
        "application/pdf",
    )
    .await
    .assert_problem(ProblemCode::ServiceUnavailable);
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_documents")
            .await,
        0
    );
}

#[tokio::test]
async fn runtime_effects_use_read_committed_despite_the_roles_default_isolation() {
    let (deployment, role) = split_deployment().await;
    deployment
        .execute(&format!(
            "ALTER ROLE {role} SET default_transaction_isolation = 'repeatable read'"
        ))
        .await;
    // The constraint proves the actual write's transaction, not a helper's
    // separate connection, has the isolation required by the fence.
    deployment
        .execute(
            "ALTER TABLE documents_versions ADD CONSTRAINT assert_admission_isolation
             CHECK (current_setting('transaction_isolation') = 'read committed')",
        )
        .await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, _) = ready_document(&prepared, &api, &pdf(512, 81)).await;
    assert_eq!(api.erase(CITIZEN, &document).await.status, 200);
    deployment.execute("UPDATE documents_versions SET erasure_requested_at = erasure_requested_at - interval '2 days', erasure_due_at = now() - interval '1 second'").await;
    prepared.sweep_due().await;
    assert_eq!(
        deployment
            .scalar::<String>("SELECT erasure_state FROM documents_versions")
            .await,
        "erased"
    );
    drop(api);
    drop(prepared);
    drop_role(&deployment, &role).await;
}

#[tokio::test]
async fn successor_activation_stops_old_verification_erasure_and_cleanup_work() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, _) = ready_document(&prepared, &api, &pdf(512, 82)).await;
    assert_eq!(api.erase(CITIZEN, &document).await.status, 200);
    deployment.execute("UPDATE documents_versions SET erasure_requested_at = erasure_requested_at - interval '2 days', erasure_due_at = now() - interval '1 second'").await;
    assert_eq!(prepared.cleanup_pass().await.unwrap().armed_erasures, 1);
    let (_, pending_version, pending_path) = reservation(
        &api.reserve(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            b"pending",
            "application/pdf",
        )
        .await,
    );
    assert_eq!(
        api.put(APP, &pending_path, "application/pdf", Body::from("pending"))
            .await
            .status,
        200
    );
    reservation(
        &api.reserve(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            b"expired",
            "application/pdf",
        )
        .await,
    );
    deployment.execute("UPDATE documents_versions SET reserved_at = reserved_at - interval '2 days', upload_expires_at = now() - interval '1 second' WHERE upload_state = 'reserved'").await;
    let calls = verifier.calls.load(std::sync::atomic::Ordering::SeqCst);
    successor(&deployment);
    deployment.migrate().await;
    assert_eq!(prepared.verify_due().await, 0);
    assert_eq!(prepared.erase_due().await, 0);
    assert!(prepared.cleanup_pass().await.is_err());
    assert_eq!(
        verifier.calls.load(std::sync::atomic::Ordering::SeqCst),
        calls
    );
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_contents")
            .await,
        2
    );
    assert_eq!(
        deployment
            .scalar::<String>("SELECT state FROM documents_erasure_jobs")
            .await,
        "pending"
    );
    assert_eq!(
        deployment
            .scalar::<i64>(
                "SELECT count(*) FROM documents_versions WHERE upload_state = 'reserved'"
            )
            .await,
        1
    );
    assert_eq!(deployment.scalar::<String>(&format!("SELECT verification_state FROM documents_versions WHERE version_id = '{pending_version}'")).await, "pending");
    drop(api);
    drop(prepared);
    let (prepared, api) = start(&deployment, &verifier).await;
    assert_eq!(prepared.verify_due().await, 1);
    assert_eq!(prepared.sweep_due().await.expired_uploads, 1);
    assert_eq!(
        deployment
            .scalar::<i64>("SELECT count(*) FROM documents_contents")
            .await,
        1
    );
    assert_eq!(api.get(CITIZEN, "/ready").await.status, 200);
}

#[tokio::test]
async fn a_verification_leased_before_activation_cannot_send_or_record_an_old_verdict() {
    use registry_documents::verification::{dispatcher, VerificationDetail, VerificationTransport};
    use registry_platform_dispatch::postgres::DispatchTransport as _;
    use registry_platform_dispatch::{SendOutcome, Sent};

    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (_prepared, api) = start(&deployment, &verifier).await;
    let (_, _, path) = reservation(
        &api.reserve(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            b"pending",
            "application/pdf",
        )
        .await,
    );
    assert_eq!(
        api.put(APP, &path, "application/pdf", Body::from("pending"))
            .await
            .status,
        200
    );
    let config = config(&deployment);
    let store = registry_documents::runtime::activated_store_for_test(&config)
        .await
        .unwrap();
    let dispatcher = dispatcher(VerificationStore::new(
        store.clone(),
        deployment.schema.clone(),
        support::worker_audit(),
        Graces::default(),
        registry_documents::runtime::activated_hooks(&config, deployment.schema.clone()).unwrap(),
    ))
    .unwrap();
    let leased = dispatcher.claim().await.unwrap().leased().unwrap();
    let storage = registry_documents::content::ContentStorage::activate(
        &config.storage,
        "registry-documents-test",
        Arc::new(config.secret_resolver().unwrap()),
    )
    .await
    .unwrap();
    let transport = VerificationTransport::new(
        store,
        Arc::new(storage),
        verifier.clone(),
        registry_documents::transfer::TransferBudget::new(1_048_576),
    );
    successor(&deployment);
    deployment.migrate().await;
    assert!(dispatcher.claim().await.is_err());
    assert!(transport.send(&leased).await.is_err());
    assert_eq!(verifier.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(dispatcher
        .finish(
            &leased,
            Sent {
                outcome: SendOutcome::Accepted {
                    receiver_reference: None
                },
                detail: VerificationDetail::Approved {
                    binding: "binding-a".to_owned()
                },
            }
        )
        .await
        .is_err());
    assert_eq!(
        deployment
            .scalar::<String>("SELECT verification_state FROM documents_versions")
            .await,
        "pending"
    );
    assert_eq!(
        deployment
            .scalar::<String>("SELECT state FROM documents_verification_jobs")
            .await,
        "leased"
    );
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
    let error = replay_verification(&deployment.runtime, &config(&deployment), version, 2)
        .await
        .expect_err("a stale generation is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Replay(ReplayRefusal::StaleGeneration { current: 1 })
        ),
        "{error}"
    );

    let replayed = replay_verification(&deployment.runtime, &config(&deployment), version, 1)
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
    let error = replay_verification(&deployment.runtime, &config(&deployment), version, 2)
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
async fn replay_refuses_a_project_hook_whose_destination_is_not_bound_as_serve_does() {
    let project = STARTER_PROJECT.replace(
        "destinationId: owning-system-events",
        "destinationId: unbound-events",
    );
    let deployment = Deployment::with_project(DATABASE_STORAGE, DISABLED_VERIFIER, &project).await;
    deployment.migrate().await;
    let error = replay_verification(&deployment.runtime, &config(&deployment), Uuid::new_v4(), 1)
        .await
        .expect_err("an unbound hook destination refuses the replay");
    // The refusal is the positioned report `documents serve` gives for the
    // same files: one diagnostic at `/destinations/hooks`, on its line of
    // the runtime document.
    let RuntimeError::ConfigurationRefused(report) = &error else {
        panic!("a positioned configuration refusal, not {error}");
    };
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect();
    assert_eq!(
        found,
        [(
            "documents.runtime.unbound-hook-destination",
            "/destinations/hooks"
        )]
    );
    let source = report.diagnostics()[0]
        .source
        .as_ref()
        .expect("the diagnostic names its file");
    assert_eq!(source.file, deployment.runtime.display().to_string());
    assert!(source.line.is_some(), "{error}");
}

#[tokio::test]
async fn replay_refuses_an_unknown_version_and_an_unactivated_database() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    let error = replay_verification(&deployment.runtime, &config(&deployment), Uuid::new_v4(), 1)
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

    let error = dead_lettered_erasures(&config(&deployment), 50)
        .await
        .expect_err("an unactivated database is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::NotActivated)
        ),
        "{error}"
    );
    let error = replay_erasure(&config(&deployment), Uuid::new_v4(), 1)
        .await
        .expect_err("an unactivated database is refused");
    assert!(
        matches!(
            error,
            RuntimeError::Activation(ActivationError::NotActivated)
        ),
        "{error}"
    );
    let error = erasure_report(&config(&deployment))
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
    let error = replay_verification(&deployment.runtime, &config(&deployment), Uuid::new_v4(), 1)
        .await
        .expect_err("an unknown version is refused");
    assert!(
        matches!(error, RuntimeError::Replay(ReplayRefusal::NotFound)),
        "{error}"
    );
    let error = replay_erasure(&config(&deployment), Uuid::new_v4(), 1)
        .await
        .expect_err("an unknown version is refused");
    assert!(
        matches!(error, RuntimeError::ErasureReplay(ReplayRefusal::NotFound)),
        "{error}"
    );
}

/// An audit sink that keeps its first `lines` lines and refuses every
/// write after them.
struct LimitedSink {
    lines: usize,
}

impl std::io::Write for LimitedSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.lines == 0 {
            return Err(std::io::Error::other("the audit sink refuses"));
        }
        self.lines -= bytes.iter().filter(|byte| **byte == b'\n').count();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Replay `version` at generation 1 with an audit journal that accepts
/// only its first `lines` lines.
async fn replay_audited(
    deployment: &Deployment,
    version: Uuid,
    lines: usize,
) -> Result<registry_documents::verification::Replayed, ReplayError> {
    let config = config(deployment);
    let store = registry_documents::runtime::activated_store_for_test(&config)
        .await
        .unwrap();
    let audit = DocumentsAudit::new(
        AuditWriter::from_line_sink(Box::new(LimitedSink { lines })),
        AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
            b"documents-test-audit-key-not-a-secret".to_vec(),
        ))
        .unwrap()
        .key_hasher(),
    );
    let verification = VerificationStore::new(
        store.clone(),
        deployment.schema.clone(),
        audit,
        Graces::default(),
        registry_documents::runtime::activated_hooks(&config, deployment.schema.clone()).unwrap(),
    );
    replay(&store, verification, version, 1).await
}

/// The job's state and generation.
async fn job(deployment: &Deployment) -> (String, i64) {
    (
        deployment
            .scalar("SELECT state FROM documents_verification_jobs")
            .await,
        deployment
            .scalar("SELECT generation FROM documents_verification_jobs")
            .await,
    )
}

#[tokio::test]
async fn a_replay_whose_audit_request_is_refused_changes_nothing() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let version = dead_lettered(&deployment, &prepared, &api).await;

    let error = replay_audited(&deployment, version, 0)
        .await
        .expect_err("an unaudited replay is refused");
    assert!(
        matches!(error, ReplayError::Failed(ReplayFailure::AuditUnavailable)),
        "{error}"
    );
    assert_eq!(job(&deployment).await, ("dead-lettered".to_owned(), 1));
}

#[tokio::test]
async fn a_replay_whose_audit_response_is_refused_stands_and_says_so() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let version = dead_lettered(&deployment, &prepared, &api).await;

    let error = replay_audited(&deployment, version, 1)
        .await
        .expect_err("a replay whose response was not audited is reported");
    assert!(
        matches!(
            &error,
            ReplayError::Failed(ReplayFailure::Unaudited { version_id, generation: 2 })
                if *version_id == version
        ),
        "{error}"
    );
    assert_eq!(job(&deployment).await, ("pending".to_owned(), 2));
}

/// Move the runtime's audit journal under `name`, where the `documentsctl`
/// companion journal is a directory and cannot be opened for writing.
fn block_operator_journal(deployment: &Deployment, name: &str) {
    let blocked = deployment.path().join(name);
    std::fs::create_dir_all(blocked.join("audit.documentsctl.ndjson")).unwrap();
    rewrite_runtime(
        deployment,
        &format!("path: {}", deployment.audit_path().display()),
        &format!("path: {}", blocked.join("audit.ndjson").display()),
    );
}

#[tokio::test]
async fn apply_fails_closed_on_an_unwritable_audit_journal() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    block_operator_journal(&deployment, "blocked");
    let error = apply_activation(&config(&deployment), &ApplyRequest::default())
        .await
        .expect_err("apply refuses an unwritable audit journal");
    assert!(matches!(error, RuntimeError::AuditJournal(_)), "{error}");
    assert_eq!(relations(&deployment).await, 0, "apply wrote nothing");
}

#[tokio::test]
async fn replay_fails_closed_on_an_unwritable_audit_journal() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let version = dead_lettered(&deployment, &prepared, &api).await;
    block_operator_journal(&deployment, "blocked");
    let error = replay_verification(&deployment.runtime, &config(&deployment), version, 1)
        .await
        .expect_err("replay refuses an unwritable audit journal");
    assert!(matches!(error, RuntimeError::AuditJournal(_)), "{error}");
    assert_eq!(job(&deployment).await, ("dead-lettered".to_owned(), 1));
}

#[tokio::test]
async fn the_dead_letter_listing_skips_jobs_under_a_former_binding_before_its_limit() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let version = dead_lettered(&deployment, &prepared, &api).await;
    // An older dead letter under a binding the version no longer carries.
    deployment
        .execute(
            "CREATE TEMPORARY TABLE former AS SELECT * FROM documents_verification_jobs;
             UPDATE former SET part = 'sha256:former-binding',
                               dead_lettered_at = dead_lettered_at - interval '1 hour';
             INSERT INTO documents_verification_jobs SELECT * FROM former;
             DROP TABLE former;",
        )
        .await;

    let listed = dead_lettered_verifications(&config(&deployment), 1)
        .await
        .expect("the dead letters list");
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0].version_id, version);
    assert_eq!(listed[0].generation, 1);
}

/// Content verification is never replayed for a version whose erasure is
/// pending or done, or whose document has a removal requested: the bytes
/// are leaving, and no verdict on them is recorded. Each refusal changes
/// nothing.
#[tokio::test]
async fn replay_refuses_a_verification_whose_content_is_being_removed() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let version = dead_lettered(&deployment, &prepared, &api).await;

    for (state, reason) in [
        (
            "UPDATE documents_documents SET removal_requested_at = now()",
            "the version's document has a removal requested",
        ),
        (
            "UPDATE documents_documents SET removal_requested_at = NULL;
             UPDATE documents_versions
                SET erasure_state = 'pending', erasure_requested_at = now(),
                    erasure_due_at = now() + interval '1 day'",
            "the version's erasure is pending",
        ),
        (
            "UPDATE documents_versions
                SET erasure_state = 'erased', erasure_due_at = erasure_requested_at,
                    erased_at = now()",
            "the version is erased",
        ),
    ] {
        deployment.execute(state).await;
        let error = replay_verification(&deployment.runtime, &config(&deployment), version, 1)
            .await
            .expect_err("a replay of content being removed is refused");
        assert!(
            matches!(
                &error,
                RuntimeError::Replay(ReplayRefusal::RemovalRequested { reason: refused })
                    if *refused == reason
            ),
            "{error}"
        );
        assert_eq!(job(&deployment).await, ("dead-lettered".to_owned(), 1));
    }
    let journal = deployment.path().join("audit.documentsctl.ndjson");
    let replayed = std::fs::read_to_string(&journal)
        .unwrap_or_default()
        .contains("\"transition\":\"replayed\"");
    assert!(!replayed, "a refused replay is not audited as a replay");
}

/// Upload and approve one document, ask for its removal, let its grace
/// pass, and dead-letter the erasure job the cleanup pass arms for it.
async fn erasure_dead_lettered(deployment: &Deployment, prepared: &Prepared, api: &Api) -> Uuid {
    let content = pdf(256, 22);
    let reserved = api
        .reserve(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            &content,
            "application/pdf",
        )
        .await;
    let (document, version, path) = reservation(&reserved);
    let put = api
        .put(APP, &path, "application/pdf", Body::from(content))
        .await;
    assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    assert_eq!(prepared.verify_due().await, 1);
    let erased = api.erase(CITIZEN, &document).await;
    assert_eq!(
        erased.status,
        200,
        "{}",
        String::from_utf8_lossy(&erased.body)
    );
    deployment
        .execute(
            "UPDATE documents_versions
                SET erasure_requested_at = erasure_requested_at - interval '2 days',
                    erasure_due_at = now() - interval '1 second'",
        )
        .await;
    assert_eq!(prepared.cleanup_pass().await.unwrap().armed_erasures, 1);
    deployment
        .execute(&format!(
            "UPDATE documents_erasure_jobs
                SET state = 'dead-lettered', attempt = {}, next_attempt_at = NULL,
                    dead_lettered_at = now()",
            registry_documents::erasure::MAXIMUM_ATTEMPTS
        ))
        .await;
    version.parse().unwrap()
}

/// The erasure job's state and generation.
async fn erasure_job(deployment: &Deployment) -> (String, i64) {
    (
        deployment
            .scalar("SELECT state FROM documents_erasure_jobs")
            .await,
        deployment
            .scalar("SELECT generation FROM documents_erasure_jobs")
            .await,
    )
}

#[tokio::test]
async fn erasure_replay_returns_a_dead_lettered_erasure_to_pending() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let version = erasure_dead_lettered(&deployment, &prepared, &api).await;

    // The sweep never re-arms a dead-lettered erasure: only a replay does.
    prepared.sweep_due().await;
    assert_eq!(
        erasure_job(&deployment).await,
        ("dead-lettered".to_owned(), 1)
    );
    let erasure: String = deployment
        .scalar("SELECT erasure_state FROM documents_versions")
        .await;
    assert_eq!(erasure, "pending");
    assert_eq!(
        erasure_report(&config(&deployment)).await.unwrap(),
        ErasureStatus {
            erasure: registry_documents::config::Erasure::Active,
            awaiting_grace: 0,
            due: 1,
            dead_lettered: 1,
        }
    );

    let listed = dead_lettered_erasures(&config(&deployment), 50)
        .await
        .expect("the dead letters list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].version_id, version);
    assert_eq!(listed[0].generation, 1);
    assert_eq!(
        listed[0].attempt,
        registry_documents::erasure::MAXIMUM_ATTEMPTS
    );

    // A stale generation is refused and changes nothing.
    let error = replay_erasure(&config(&deployment), version, 2)
        .await
        .expect_err("a stale generation is refused");
    assert!(
        matches!(
            error,
            RuntimeError::ErasureReplay(ReplayRefusal::StaleGeneration { current: 1 })
        ),
        "{error}"
    );
    assert_eq!(
        erasure_job(&deployment).await,
        ("dead-lettered".to_owned(), 1)
    );

    let replayed = replay_erasure(&config(&deployment), version, 1)
        .await
        .expect("the dead letter replays");
    assert_eq!(replayed.version_id, version);
    assert_eq!(replayed.generation, 2);
    let pending: bool = deployment
        .scalar(
            "SELECT state = 'pending' AND generation = 2 AND attempt = 0
               FROM documents_erasure_jobs",
        )
        .await;
    assert!(pending, "the job is pending again under a new generation");
    assert!(dead_lettered_erasures(&config(&deployment), 50)
        .await
        .unwrap()
        .is_empty());

    // The replay is audited, begun and finished, in the operator's
    // companion journal.
    let journal = std::fs::read_to_string(deployment.path().join("audit.documentsctl.ndjson"))
        .expect("a documentsctl companion audit journal");
    let replays = journal
        .lines()
        .filter(|line| {
            line.contains("\"event\":\"documents.erasure\"")
                && line.contains("\"transition\":\"replayed\"")
                && line.contains(&version.to_string())
        })
        .collect::<Vec<_>>();
    assert_eq!(replays.len(), 2, "{journal}");
    assert!(
        replays[0].contains("\"outcome\":\"requested\""),
        "{journal}"
    );
    assert!(
        replays[1].contains("\"outcome\":\"committed\""),
        "{journal}"
    );

    // The job is no longer dead-lettered, so a second replay is refused.
    let error = replay_erasure(&config(&deployment), version, 2)
        .await
        .expect_err("a pending job is not replayed");
    assert!(
        matches!(
            &error,
            RuntimeError::ErasureReplay(ReplayRefusal::NotDeadLettered { state }) if state == "pending"
        ),
        "{error}"
    );

    // The replayed job erases the bytes like any other.
    prepared.sweep_due().await;
    let (erasure, held): (String, i64) = (
        deployment
            .scalar("SELECT erasure_state FROM documents_versions")
            .await,
        deployment
            .scalar("SELECT count(*) FROM documents_contents")
            .await,
    );
    assert_eq!((erasure.as_str(), held), ("erased", 0));
}

/// Replay the erasure of `version` at generation 1 with an audit journal
/// that accepts only its first `lines` lines.
async fn erasure_replay_audited(
    deployment: &Deployment,
    version: Uuid,
    lines: usize,
) -> Result<registry_documents::replay::Replayed, ReplayError> {
    let config = config(deployment);
    let store = registry_documents::runtime::activated_store_for_test(&config)
        .await
        .unwrap();
    let audit = DocumentsAudit::new(
        AuditWriter::from_line_sink(Box::new(LimitedSink { lines })),
        AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
            b"documents-test-audit-key-not-a-secret".to_vec(),
        ))
        .unwrap()
        .key_hasher(),
    );
    let erasure = ErasureStore::new(store.clone(), deployment.schema.clone(), audit);
    registry_documents::erasure::replay(&store, erasure, version, 1).await
}

#[tokio::test]
async fn an_erasure_replay_whose_audit_request_is_refused_changes_nothing() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let version = erasure_dead_lettered(&deployment, &prepared, &api).await;

    let error = erasure_replay_audited(&deployment, version, 0)
        .await
        .expect_err("an unaudited replay is refused");
    assert!(
        matches!(error, ReplayError::Failed(ReplayFailure::AuditUnavailable)),
        "{error}"
    );
    assert_eq!(
        erasure_job(&deployment).await,
        ("dead-lettered".to_owned(), 1)
    );
}

#[tokio::test]
async fn an_erasure_replay_whose_audit_response_is_refused_stands_and_says_so() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let version = erasure_dead_lettered(&deployment, &prepared, &api).await;

    let error = erasure_replay_audited(&deployment, version, 1)
        .await
        .expect_err("a replay whose response was not audited is reported");
    assert!(
        matches!(
            &error,
            ReplayError::Failed(ReplayFailure::Unaudited { version_id, generation: 2 })
                if *version_id == version
        ),
        "{error}"
    );
    assert_eq!(erasure_job(&deployment).await, ("pending".to_owned(), 2));
}

#[tokio::test]
async fn erasure_replay_fails_closed_on_an_unwritable_audit_journal() {
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let version = erasure_dead_lettered(&deployment, &prepared, &api).await;
    block_operator_journal(&deployment, "blocked");
    let error = replay_erasure(&config(&deployment), version, 1)
        .await
        .expect_err("replay refuses an unwritable audit journal");
    assert!(matches!(error, RuntimeError::AuditJournal(_)), "{error}");
    assert_eq!(
        erasure_job(&deployment).await,
        ("dead-lettered".to_owned(), 1)
    );
}

/// A replayed erasure waits while erasure is paused: the replay returns the
/// job to pending, and the paused runtime erases nothing until resumed.
#[tokio::test]
async fn a_replayed_erasure_waits_while_erasure_is_paused() {
    let mut deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let version = erasure_dead_lettered(&deployment, &prepared, &api).await;
    drop(api);
    drop(prepared);
    deployment.set_erasure("paused");
    let (paused, _api) = start(&deployment, &verifier).await;
    assert_eq!(
        erasure_report(&config(&deployment)).await.unwrap().erasure,
        registry_documents::config::Erasure::Paused
    );

    replay_erasure(&config(&deployment), version, 1)
        .await
        .expect("a paused deployment still replays");
    paused.sweep_due().await;
    let held: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    assert_eq!(held, 1, "a paused runtime runs no replayed erasure");
    assert_eq!(erasure_job(&deployment).await, ("pending".to_owned(), 2));
}
