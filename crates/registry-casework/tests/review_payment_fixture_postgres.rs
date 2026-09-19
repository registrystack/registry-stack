#![cfg(feature = "postgres-test")]

use std::{
    collections::BTreeSet,
    env,
    sync::{Arc, Mutex},
};

use registry_casework::{
    CaseworkService, DatabaseConfig, PostgresStore, ReviewResultRead, ReviewTaskDecisionRequest,
};
use registry_casework_core::{
    AccessProfile, ActorContext, CaseworkIdentity, CaseworkProject, CaseworkRole, ContentDigest,
    InboxPolicy, IssuerPrincipal, QueuePolicy, ReviewCompletion, ReviewCompletionDestinationPolicy,
    ReviewCompletionType, ReviewContext, ReviewContextStrategy, ReviewCreateRequest,
    ReviewKindPolicy, ReviewKindPurpose, ReviewProducerPolicy, ReviewResult, ReviewResultStatus,
    ReviewRetentionPolicy, ReviewStagePolicy, ReviewerDecisionKind, SubjectBinding,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
use tokio_postgres::NoTls;
use uuid::Uuid;

const ISSUER: &str = "https://payments.example.test";
const BATCH_ID: &str = "batch-2026-09";

#[derive(Clone, Debug, Eq, PartialEq)]
enum PaymentBatchState {
    Draft,
    Submitted,
    Released { receipt: String },
}

#[derive(Clone, Debug)]
struct PaymentBatch {
    id: String,
    version: String,
    digest: ContentDigest,
    amount_minor: u64,
    state: PaymentBatchState,
}

#[derive(Clone, Default)]
struct PaymentStore {
    batch: Arc<Mutex<Option<PaymentBatch>>>,
    completion_events: Arc<Mutex<BTreeSet<Uuid>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PaymentError {
    InvalidBatch,
    NotSubmitted,
    NotAuthorized,
    ReviewMismatch,
    NotApproved,
}

impl PaymentStore {
    fn create(&self, amount_minor: u64) -> Result<(), PaymentError> {
        if amount_minor == 0 {
            return Err(PaymentError::InvalidBatch);
        }
        let digest = ContentDigest::for_bytes(format!("{BATCH_ID}:1:{amount_minor}").as_bytes());
        *self.batch.lock().expect("payment batch lock") = Some(PaymentBatch {
            id: BATCH_ID.to_owned(),
            version: "1".to_owned(),
            digest,
            amount_minor,
            state: PaymentBatchState::Draft,
        });
        Ok(())
    }

    fn submit_for_review(&self) -> Result<ReviewCreateRequest, PaymentError> {
        let mut guard = self.batch.lock().expect("payment batch lock");
        let batch = guard.as_mut().ok_or(PaymentError::InvalidBatch)?;
        if batch.state != PaymentBatchState::Draft || batch.amount_minor == 0 {
            return Err(PaymentError::InvalidBatch);
        }
        batch.state = PaymentBatchState::Submitted;
        Ok(ReviewCreateRequest {
            kind: "payment-batch".to_owned(),
            subject: SubjectBinding {
                source: "payments".to_owned(),
                subject_type: "payment_batch".to_owned(),
                id: batch.id.clone(),
                version: batch.version.clone(),
                digest: batch.digest.clone(),
            },
            requester_reference: "payment-review-2026-09".to_owned(),
            initiator: None,
            context: ReviewContext::Submitted {
                snapshot: json!({
                    "batchId": batch.id,
                    "amountMinor": batch.amount_minor,
                    "currency": "USD"
                }),
            },
            result_constraints: None,
        })
    }

    /// A completion is only a deduplicated wake-up signal. It carries no
    /// approval evidence and cannot release a payment by itself.
    fn accept_completion(&self, completion: &ReviewCompletion) -> bool {
        self.completion_events
            .lock()
            .expect("completion inbox lock")
            .insert(completion.event_id)
    }

    fn release(
        &self,
        executor_is_currently_authorized: bool,
        result: &ReviewResult,
    ) -> Result<String, PaymentError> {
        if !executor_is_currently_authorized {
            return Err(PaymentError::NotAuthorized);
        }
        if result.status != ReviewResultStatus::Approved {
            return Err(PaymentError::NotApproved);
        }
        let mut guard = self.batch.lock().expect("payment batch lock");
        let batch = guard.as_mut().ok_or(PaymentError::InvalidBatch)?;
        if let PaymentBatchState::Released { receipt } = &batch.state {
            return Ok(receipt.clone());
        }
        if batch.state != PaymentBatchState::Submitted {
            return Err(PaymentError::NotSubmitted);
        }
        if result.subject.source != "payments"
            || result.subject.subject_type != "payment_batch"
            || result.subject.id != batch.id
            || result.subject.version != batch.version
            || result.subject.digest != batch.digest
            || result.policy.id != "payment-batch"
        {
            return Err(PaymentError::ReviewMismatch);
        }
        let receipt = format!("payment-release:{}:{}", batch.id, batch.version);
        batch.state = PaymentBatchState::Released {
            receipt: receipt.clone(),
        };
        Ok(receipt)
    }
}

fn profile(id: &str, role: CaseworkRole) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        principal_claim: "sub".to_owned(),
        required_scopes: vec![format!("casework:{id}")],
        role,
        kinds: Vec::new(),
    }
}

fn actor(subject: &str, role: CaseworkRole, profile_id: &str) -> ActorContext {
    ActorContext {
        principal: IssuerPrincipal {
            issuer: ISSUER.to_owned(),
            subject: subject.to_owned(),
        },
        profile_id: profile_id.to_owned(),
        role,
    }
}

fn project() -> CaseworkProject {
    CaseworkProject {
        api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
        kind: registry_casework_core::CASEWORK_KIND.to_owned(),
        casework: CaseworkIdentity {
            id: "payment-review-fixture".to_owned(),
            version: "1".to_owned(),
        },
        access_profiles: vec![
            profile("reviewer", CaseworkRole::Staff),
            profile("supervisor", CaseworkRole::Supervisor),
            profile("administrator", CaseworkRole::Administrator),
            profile("payments", CaseworkRole::Requester),
        ],
        queues: vec![QueuePolicy {
            id: "payment-review".to_owned(),
            label: "Payment review".to_owned(),
        }],
        sources: Vec::new(),
        hosted_kinds: Vec::new(),
        review_kinds: vec![ReviewKindPolicy {
            id: "payment-batch".to_owned(),
            version: "1".to_owned(),
            purpose: ReviewKindPurpose::Approval,
            context_strategy: ReviewContextStrategy::Submitted,
            stages: vec![ReviewStagePolicy {
                id: "verification".to_owned(),
                queue: "payment-review".to_owned(),
                deciding_profiles: vec!["reviewer".to_owned()],
                required_approvals: 1,
                exclude_initiator: false,
                exclude_previous_stage_reviewers: false,
            }],
            clocks: Vec::new(),
            retention: ReviewRetentionPolicy {
                terminal_days: 30,
                accountability_days: 90,
            },
            display_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["batchId", "amountMinor", "currency"],
                "properties": {
                    "batchId": {"type": "string", "maxLength": 80},
                    "amountMinor": {"type": "integer", "minimum": 1},
                    "currency": {"type": "string", "enum": ["USD"]}
                }
            }),
            result_schema: None,
            outcomes: Vec::new(),
        }],
        review_producers: vec![ReviewProducerPolicy {
            id: "payments".to_owned(),
            profile: "payments".to_owned(),
            issuer: ISSUER.to_owned(),
            subject: "payment-service".to_owned(),
            trusted_initiator_issuer: None,
            source_namespaces: vec!["payments".to_owned()],
            kinds: vec!["payment-batch".to_owned()],
            recovery_days: 7,
            completion: Some(ReviewCompletionDestinationPolicy {
                destination_id: "payment-results".to_owned(),
                recipient_binding: "payment-service".to_owned(),
            }),
        }],
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
        task_templates: Vec::new(),
    }
}

async fn fixture() -> (CaseworkService, tokio_postgres::Client) {
    let base = env::var("CASEWORK_REVIEW_TEST_DATABASE_URL")
        .expect("CASEWORK_REVIEW_TEST_DATABASE_URL is required for the payment fixture");
    let schema = format!("review_payment_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let (admin, admin_connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("connect dedicated payment fixture database");
    tokio::spawn(async move { admin_connection.await.expect("admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create isolated payment schema");

    let secret_name =
        format!("CASEWORK_PAYMENT_SCHEMA_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    env::set_var(&secret_name, &scoped_url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("payment fixture secret resolver");
    let database_config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret_name}"),
        migration_url_ref: format!("secret:env/{secret_name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    PostgresStore::connect_migration(&database_config, &secrets)
        .expect("payment migration store")
        .migrate()
        .await
        .expect("payment fixture migrations");
    let store =
        PostgresStore::connect_runtime(&database_config, &secrets).expect("payment runtime store");
    let (database, connection) = tokio_postgres::connect(&scoped_url, NoTls)
        .await
        .expect("payment schema connection");
    tokio::spawn(async move { connection.await.expect("payment schema connection task") });
    database
        .batch_execute(
            "INSERT INTO casework_teams(team_id,revision) VALUES('payment-team',1);
             INSERT INTO casework_queue_service(queue_id,team_id,revision)
             VALUES('payment-review','payment-team',1);
             INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind)
             VALUES('payment-team','https://payments.example.test','reviewer','staff');",
        )
        .await
        .expect("seed payment reviewer");
    let project = project();
    project.check().expect("payment review project");
    let service = CaseworkService::new(
        store,
        project,
        Vec::<Arc<dyn registry_casework_core::SourceAdapter>>::new(),
    )
    .expect("payment review service");
    (service, database)
}

#[tokio::test]
async fn independent_payment_source_uses_casework_but_retains_release_authority() {
    let (service, database) = fixture().await;
    let payments = PaymentStore::default();
    payments.create(125_00).expect("valid payment batch");
    let request = payments.submit_for_review().expect("freeze payment batch");
    let producer = actor("payment-service", CaseworkRole::Requester, "payments");
    let reviewer = actor("reviewer", CaseworkRole::Staff, "reviewer");
    let accepted = service
        .create_review_request(&producer, request, "submit-payment-batch")
        .await
        .expect("submit payment review")
        .accepted;
    let task_id: Uuid = database
        .query_one(
            "SELECT task_id FROM casework_review_tasks WHERE request_id=$1",
            &[&accepted.request_id],
        )
        .await
        .expect("payment review task")
        .get(0);
    service
        .claim_review_task(&reviewer, task_id, None, "", 1, "claim-payment-review")
        .await
        .expect("claim payment review");
    service
        .decide_review_task(
            &reviewer,
            task_id,
            ReviewTaskDecisionRequest {
                decision: ReviewerDecisionKind::Approve,
            },
            None,
            "",
            2,
            "approve-payment-review",
        )
        .await
        .expect("approve payment review");

    let result = match service
        .review_result(&producer, accepted.request_id)
        .await
        .expect("read payment result")
    {
        ReviewResultRead::Available(result) => *result,
        other => panic!("expected available payment result, got {other:?}"),
    };
    let completion = ReviewCompletion {
        event_type: ReviewCompletionType::ReviewCompleted,
        event_id: result.result_id,
        request_id: result.request_id,
        result_id: result.result_id,
        completed_at: result.completed_at,
    };
    assert!(payments.accept_completion(&completion));
    assert!(!payments.accept_completion(&completion));

    assert_eq!(
        payments.release(false, &result),
        Err(PaymentError::NotAuthorized)
    );
    let mut substituted = result.clone();
    substituted.subject.digest = ContentDigest::for_bytes(b"another payment batch");
    assert_eq!(
        payments.release(true, &substituted),
        Err(PaymentError::ReviewMismatch)
    );
    let receipt = payments
        .release(true, &result)
        .expect("authorized exact payment release");
    assert_eq!(
        payments
            .release(true, &result)
            .expect("recover payment receipt"),
        receipt
    );
}
