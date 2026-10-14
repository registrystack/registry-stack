use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use std::{collections::BTreeMap, time::Duration};
use tokio_postgres::error::SqlState;
use tower::ServiceExt;

const ISSUER: &str = "https://task-token.test";

struct AbortOnDrop<T>(Option<tokio::task::JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(Some(handle))
    }

    async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        let result = self.0.as_mut().unwrap().await;
        self.0.take();
        result
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
}

async fn store_for_schema(schema: &str, application_name: &str) -> PostgresStore {
    let base = std::env::var("CASEWORK_ASSIGNMENT_TEST_DATABASE_URL")
        .expect("disposable database is required");
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!(
        "{base}{separator}options=-csearch_path%3D{schema}&application_name={application_name}"
    );
    let secret_name =
        format!("CASEWORK_LOCK_ORDER_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&secret_name, &url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp").unwrap();
    let config = crate::DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret_name}"),
        migration_url_ref: format!("secret:env/{secret_name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let store = PostgresStore::connect_runtime(&config, &secrets)
        .expect("connect lock-order store")
        .with_audit(crate::CaseworkAudit::capture().0);
    std::env::remove_var(secret_name);
    store
}

async fn wait_for_blocked_query(
    database: &tokio_postgres::Client,
    application_name: &str,
    query_fragment: &str,
) -> i32 {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(row) = database
                .query_opt(
                    "SELECT pid FROM pg_stat_activity
                     WHERE datname=current_database() AND application_name=$1
                       AND wait_event_type='Lock'
                       AND cardinality(pg_blocking_pids(pid))>0
                       AND query LIKE '%' || $2 || '%'
                     ORDER BY pid LIMIT 1",
                    &[&application_name, &query_fragment],
                )
                .await
                .expect("inspect blocked database query")
            {
                return row.get(0);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("query reaches the expected database lock wait")
}

async fn wait_for_query_queued_behind(
    database: &tokio_postgres::Client,
    application_name: &str,
    earlier_waiter: i32,
    excluded: &[i32],
) -> i32 {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(row) = database
                .query_opt(
                    "SELECT pid FROM pg_stat_activity
                     WHERE datname=current_database() AND application_name=$1
                       AND wait_event_type='Lock'
                       AND NOT (pid=ANY($2))
                       AND $3=ANY(pg_blocking_pids(pid))
                     ORDER BY pid LIMIT 1",
                    &[&application_name, &excluded, &earlier_waiter],
                )
                .await
                .expect("inspect database lock queue")
            {
                return row.get(0);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("later query queues behind the earlier request-row waiter")
}

async fn decide(app: Router, task_id: Uuid, token: String) -> StatusCode {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(format!("/v1/review-tasks/{task_id}/decisions"))
            .header("authorization", format!("Bearer {token}"))
            .header(CASEWORK_PROFILE_HEADER, "staff")
            .header(SOURCE_PROFILE_HEADER, "source-reader")
            .header("content-type", "application/json")
            .header(IF_MATCH_HEADER, "\"1\"")
            .header(IDEMPOTENCY_KEY_HEADER, "lock-order-decision")
            .body(Body::from(
                serde_json::to_vec(&ReviewTaskDecisionRequest {
                    decision: DecisionKind::Approve,
                })
                .unwrap(),
            ))
            .unwrap(),
    )
    .await
    .expect("decision response")
    .status()
}

#[tokio::test]
async fn grant_approval_and_decision_lock_request_before_task_without_deadlock() {
    let fixture = super::http_tests::fixture(900).await;
    let application_name = format!("casework-grant-lock-{}", Uuid::new_v4().simple());
    let store = store_for_schema(&fixture.schema, &application_name).await;
    let app = super::http_tests::test_app(
        &store,
        &fixture.project,
        fixture.mode.clone(),
        fixture.read_started.clone(),
        fixture.read_continue.clone(),
    );
    let actor = ActorContext {
        principal: IssuerPrincipal {
            issuer: ISSUER.into(),
            subject: "human".into(),
        },
        profile_id: "staff".into(),
        role: CaseworkRole::Staff,
    };
    let request_id: Uuid = store
        .client()
        .await
        .unwrap()
        .query_one(
            "SELECT request_id FROM casework_review_tasks WHERE task_id=$1",
            &[&fixture.review_task],
        )
        .await
        .unwrap()
        .get(0);
    let template = fixture.project.task_templates[0].clone();
    let now = u64::try_from(Utc::now().timestamp()).unwrap();
    let grant = ReviewTaskGrant {
        id: Uuid::new_v4(),
        task_id: fixture.review_task,
        request_id,
        task_revision: 1,
        assignment_generation: None,
        holder: actor.principal.clone(),
        template: template.clone(),
        template_digest: template_digest(&template).unwrap(),
        source_issuer: "https://task-authority.test".into(),
        approver_profile: actor.profile_id.clone(),
        subject: SubjectBinding {
            source: "source".into(),
            subject_type: "request".into(),
            id: "request-1".into(),
            version: "proposal-1".into(),
            digest: ContentDigest::for_bytes(b"request-1"),
        },
        subjects: BTreeMap::from([("person_reference".into(), json!("synthetic-person"))]),
        approved_at: now,
        expires_at: now + 900,
    };

    let monitor = store.client().await.unwrap();
    let interleaving_store = store.clone();
    let task_id = fixture.review_task;
    let decision_token =
        super::http_tests::token("human", "human-client", "human", "casework:staff");
    let mut interleaving = tokio::spawn(async move {
        let mut blocker = interleaving_store.client().await.unwrap();
        let blocker_pid: i32 = blocker
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let blocker = blocker.transaction().await.unwrap();
        blocker
            .query_one(
                "SELECT 1 FROM casework_review_requests WHERE request_id=$1 FOR UPDATE",
                &[&request_id],
            )
            .await
            .unwrap();

        let decision = AbortOnDrop::new(tokio::spawn(decide(app, task_id, decision_token)));
        let decision_pid = wait_for_blocked_query(
            &monitor,
            &application_name,
            "FROM casework_review_requests WHERE request_id=$1 FOR UPDATE",
        )
        .await;

        let approving_store = interleaving_store.clone();
        let approval = AbortOnDrop::new(tokio::spawn(async move {
            approving_store
                .approve_review_task_grant(&actor, "lock-order-approval", grant)
                .await
        }));
        let approval_pid = wait_for_query_queued_behind(
            &monitor,
            &application_name,
            decision_pid,
            &[blocker_pid, decision_pid],
        )
        .await;
        assert_ne!(approval_pid, decision_pid);

        let mut probe = interleaving_store.client().await.unwrap();
        let probe = probe.transaction().await.unwrap();
        let task_lockable = match probe
            .query_one(
                "SELECT 1 FROM casework_review_tasks WHERE task_id=$1 FOR UPDATE NOWAIT",
                &[&task_id],
            )
            .await
        {
            Ok(_) => true,
            Err(error) if error.code() == Some(&SqlState::LOCK_NOT_AVAILABLE) => false,
            Err(error) => panic!("unexpected task lock probe failure: {error}"),
        };
        probe.rollback().await.unwrap();

        blocker.commit().await.unwrap();
        let decision_status = tokio::time::timeout(Duration::from_secs(10), decision.join())
            .await
            .expect("decision finishes after request fence release")
            .expect("decision task");
        let approval_result = tokio::time::timeout(Duration::from_secs(10), approval.join())
            .await
            .expect("approval finishes after request fence release")
            .expect("approval task");
        (task_lockable, decision_status, approval_result)
    });
    let interleaving_result =
        tokio::time::timeout(Duration::from_secs(30), &mut interleaving).await;
    if interleaving_result.is_err() {
        interleaving.abort();
        let _ = interleaving.await;
    }

    fixture
        .admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", fixture.schema))
        .await
        .unwrap();

    let (task_lockable, decision_status, approval_result) = interleaving_result
        .expect("bounded lock-order interleaving")
        .expect("lock-order interleaving task");
    let approval_outcome = match &approval_result {
        Ok(_) => "approved".to_owned(),
        Err(StoreError::Forbidden) => "forbidden".to_owned(),
        Err(StoreError::Postgres(error))
            if error.code() == Some(&SqlState::T_R_DEADLOCK_DETECTED) =>
        {
            "deadlock-detected".to_owned()
        }
        Err(error) => error.to_string(),
    };

    assert!(
        task_lockable,
        "approval must wait on the request row without holding the task row; \
         decision={decision_status}, approval={approval_outcome}"
    );
    assert_eq!(decision_status, StatusCode::NO_CONTENT);
    assert!(
        matches!(approval_result, Err(StoreError::Forbidden)),
        "the queued approval must recheck and refuse the terminal task"
    );
}
