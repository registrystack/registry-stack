use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::sync::Arc;

use async_trait::async_trait;
use registry_casework::{CaseworkService, DatabaseConfig, PostgresStore, ServiceError};
use registry_casework_core::{
    AccessProfile, ActiveSubjectsPage, ActorContext, AuthoritativeObservation,
    BootstrapDirectoryRequest, CallerSubjectView, CaseworkIdentity, CaseworkProject, CaseworkRole,
    DiscoveryCursor, EphemeralCredential, EqualsPredicate, EventRequest, ExecutePreparedRequest,
    InboxPolicy, IssuerPrincipal, OccurrenceKind, OccurrenceState, PrepareActionRequest,
    PreparedSourceAttempt, QueuePolicy, RoutingActivity, RoutingCondition, RoutingContext,
    RoutingFieldDescriptor, RoutingPredicate, RoutingRule, RoutingSourceMetadata, SourceAdapter,
    SourceAdapterError, SourceBinding, SourcePolicy, SourceReceipt, SourceRequestPolicy,
    SubjectRef, TransitionHint, WorkItemRouting,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio_postgres::NoTls;
use uuid::Uuid;

const SOURCE_ID: &str = "routing-source";
const SOURCE_KIND: &str = "request";
const GENERATION: &str = "routing-generation-1";

#[derive(Clone)]
struct RoutingSource {
    metadata: RoutingSourceMetadata,
    observations: BTreeMap<String, AuthoritativeObservation>,
    concealed: BTreeSet<String>,
}

#[async_trait]
impl SourceAdapter for RoutingSource {
    fn source_id(&self) -> &str {
        SOURCE_ID
    }

    fn binding_generation(&self) -> &str {
        GENERATION
    }

    fn routing_metadata(&self) -> Option<&RoutingSourceMetadata> {
        Some(&self.metadata)
    }

    async fn verify_transition(
        &self,
        _request: EventRequest,
    ) -> Result<TransitionHint, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }

    async fn read_authoritative(
        &self,
        subject: &SubjectRef,
    ) -> Result<AuthoritativeObservation, SourceAdapterError> {
        self.observations
            .get(&subject.id)
            .cloned()
            .ok_or(SourceAdapterError::Invalid)
    }

    async fn discover_active(
        &self,
        _cursor: Option<&DiscoveryCursor>,
        _limit: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
        Ok(ActiveSubjectsPage {
            subjects: Vec::new(),
            next_cursor: None,
        })
    }

    async fn read_for_caller(
        &self,
        subject: &SubjectRef,
        _source_profile_id: &str,
        _credential: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        if self.concealed.contains(&subject.id) {
            return Err(SourceAdapterError::Concealed);
        }
        let observation = self
            .observations
            .get(&subject.id)
            .ok_or(SourceAdapterError::Concealed)?;
        Ok(CallerSubjectView {
            display_reference: None,
            subject: subject.clone(),
            binding: observation.binding.clone(),
            disclosed: BTreeMap::from([("summary".to_owned(), json!("caller-visible"))]),
            permitted_operations: Vec::new(),
        })
    }

    async fn prepare_action(
        &self,
        _request: PrepareActionRequest<'_>,
    ) -> Result<PreparedSourceAttempt, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }

    async fn execute_prepared(
        &self,
        _request: ExecutePreparedRequest<'_>,
    ) -> Result<SourceReceipt, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
}

fn principal(subject: &str) -> IssuerPrincipal {
    IssuerPrincipal {
        issuer: "https://issuer.test".to_owned(),
        subject: subject.to_owned(),
    }
}

fn actor(subject: &str, role: CaseworkRole, profile_id: &str) -> ActorContext {
    ActorContext {
        principal: principal(subject),
        profile_id: profile_id.to_owned(),
        role,
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

fn metadata() -> RoutingSourceMetadata {
    RoutingSourceMetadata {
        stages: vec!["legal".to_owned(), "technical".to_owned()],
        fields: vec![RoutingFieldDescriptor {
            field: "region".to_owned(),
            api_name: "region".to_owned(),
            schema: json!({"type":"string","enum":["north","south"]}),
        }],
    }
}

fn routing_project() -> CaseworkProject {
    CaseworkProject {
        task_templates: Vec::new(),
        api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
        kind: registry_casework_core::CASEWORK_KIND.to_owned(),
        casework: CaseworkIdentity {
            id: "routing-test".to_owned(),
            version: "1".to_owned(),
        },
        access_profiles: vec![
            profile("staff", CaseworkRole::Staff),
            profile("supervisor", CaseworkRole::Supervisor),
            profile("administrator", CaseworkRole::Administrator),
        ],
        queues: ["triage", "regional", "priority"]
            .into_iter()
            .map(|id| QueuePolicy {
                id: id.to_owned(),
                label: id.to_owned(),
            })
            .collect(),
        sources: vec![SourcePolicy {
            id: SOURCE_ID.to_owned(),
            adapter: "test".to_owned(),
            description: "Routing test source".to_owned(),
            requests: vec![SourceRequestPolicy {
                display_reference: None,
                entity: SOURCE_KIND.to_owned(),
                queue: "triage".to_owned(),
                projection: vec!["region".to_owned()],
                routing: vec![
                    RoutingRule {
                        id: "legal-first".to_owned(),
                        because: "Legal review has priority".to_owned(),
                        when: RoutingCondition {
                            activity: Some(RoutingActivity::Review),
                            stage: Some("legal".to_owned()),
                            fields: BTreeMap::new(),
                        },
                        queue: "priority".to_owned(),
                    },
                    RoutingRule {
                        id: "north-region".to_owned(),
                        because: "Northern work is regional".to_owned(),
                        when: RoutingCondition {
                            activity: Some(RoutingActivity::Review),
                            stage: None,
                            fields: BTreeMap::from([(
                                "region".to_owned(),
                                RoutingPredicate::Equals(EqualsPredicate {
                                    equals: json!("north"),
                                }),
                            )]),
                        },
                        queue: "regional".to_owned(),
                    },
                ],
                clock: None,
                target: None,
            }],
        }],
        hosted_kinds: Vec::new(),
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
    }
}

fn observation(id: Uuid, stage: &str, region: &str) -> AuthoritativeObservation {
    AuthoritativeObservation {
        display_reference: None,
        subject: SubjectRef {
            source_id: SOURCE_ID.to_owned(),
            kind: SOURCE_KIND.to_owned(),
            id: id.to_string(),
        },
        occurrence_key: "review:1".to_owned(),
        ordered_revision: 1,
        representation_etag: format!("\"{id}\""),
        binding: SourceBinding {
            source_revision: "1".to_owned(),
            version: "1".to_owned(),
            integrity: None,
            generation: GENERATION.to_owned(),
        },
        occurrence_kind: OccurrenceKind::Review,
        stage: Some(stage.to_owned()),
        submitted_at: None,
        stage_entered_at: None,
        review_timing: None,
        routing_context: Some(RoutingContext {
            activity: RoutingActivity::Review,
            stage: Some(stage.to_owned()),
            fields: BTreeMap::from([("region".to_owned(), json!(region))]),
        }),
        state: OccurrenceState::Open,
        remaining_actions: Vec::new(),
    }
}

async fn stores() -> (PostgresStore, tokio_postgres::Client) {
    let base = env::var("CASEWORK_ROUTING_TEST_DATABASE_URL")
        .expect("CASEWORK_ROUTING_TEST_DATABASE_URL is required");
    let schema = format!("routing_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let (admin, connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("connect routing test database");
    tokio::spawn(async move { connection.await.expect("routing admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create isolated routing schema");
    let secret_name =
        format!("CASEWORK_ROUTING_SCHEMA_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    env::set_var(&secret_name, &scoped_url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("routing test secret resolver");
    let config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret_name}"),
        migration_url_ref: format!("secret:env/{secret_name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let migration = PostgresStore::connect_migration(&config, &secrets).expect("migration store");
    migration.migrate().await.expect("routing migrations");
    let store = PostgresStore::connect_runtime(&config, &secrets).expect("runtime store");
    let (database, connection) = tokio_postgres::connect(&scoped_url, NoTls)
        .await
        .expect("connect scoped routing database");
    tokio::spawn(async move { connection.await.expect("routing schema connection") });
    (store, database)
}

async fn bootstrap_queues(store: &PostgresStore, staff: &ActorContext, supervisor: &ActorContext) {
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    for (revision, queue) in ["triage", "regional", "priority"].into_iter().enumerate() {
        store
            .bootstrap_directory(
                &administrator,
                i64::try_from(revision).expect("bounded revision"),
                &BootstrapDirectoryRequest {
                    team_id: format!("{queue}-team"),
                    staff: vec![staff.principal.clone()],
                    supervisors: vec![supervisor.principal.clone()],
                    queue_id: queue.to_owned(),
                },
                &format!("bootstrap-{queue}"),
            )
            .await
            .expect("bootstrap routing queue");
    }
}

#[tokio::test]
async fn synchronization_uses_first_matching_stage_then_region_and_falls_back_to_default() {
    let (store, database) = stores().await;
    let staff = actor("staff", CaseworkRole::Staff, "staff");
    let supervisor = actor("supervisor", CaseworkRole::Supervisor, "supervisor");
    bootstrap_queues(&store, &staff, &supervisor).await;
    let both = Uuid::new_v4();
    let regional = Uuid::new_v4();
    let fallback = Uuid::new_v4();
    let concealed = Uuid::new_v4();
    let observations = [
        observation(both, "legal", "north"),
        observation(regional, "technical", "north"),
        observation(fallback, "technical", "south"),
        observation(concealed, "technical", "north"),
    ];
    let project = routing_project();
    let policy = &project.sources[0].requests[0];
    let canonical = registry_platform_canonical_json::canonicalize_json(&json!({
        "entity": &policy.entity,
        "queue": &policy.queue,
        "projection": &policy.projection,
        "routing": &policy.routing,
    }))
    .expect("routing policy canonicalizes");
    let expected_policy_digest = format!(
        "sha256:{}",
        Sha256::digest(canonical)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let source = Arc::new(RoutingSource {
        metadata: metadata(),
        observations: observations
            .iter()
            .cloned()
            .map(|observation| (observation.subject.id.clone(), observation))
            .collect(),
        concealed: BTreeSet::from([concealed.to_string()]),
    });
    let service = CaseworkService::new(store.clone(), project, [source as Arc<dyn SourceAdapter>])
        .expect("routing service starts with matching source metadata");
    let subjects = observations
        .iter()
        .map(|observation| observation.subject.clone())
        .collect::<Vec<_>>();
    store
        .enqueue_discovered(GENERATION, &subjects)
        .await
        .expect("enqueue routing subjects");
    assert_eq!(
        service
            .synchronize_pending(10)
            .await
            .expect("synchronize routed work"),
        4
    );

    for (subject_id, expected_queue, expected_rule, expected_because) in [
        (
            both,
            "priority",
            Some("legal-first"),
            Some("Legal review has priority"),
        ),
        (
            regional,
            "regional",
            Some("north-region"),
            Some("Northern work is regional"),
        ),
        (fallback, "triage", None, None),
    ] {
        let item_id: Uuid = database
            .query_one(
                "SELECT item_id FROM casework_items WHERE subject_id=$1",
                &[&subject_id.to_string()],
            )
            .await
            .expect("routed item exists")
            .get(0);
        let (item, view) = service
            .caller_item(&staff, item_id, "source-profile", "ephemeral-token")
            .await
            .expect("current team member can read routed work");
        assert_eq!(item.queue_id, expected_queue);
        assert_eq!(
            item.routing,
            Some(WorkItemRouting {
                rule_id: expected_rule.map(str::to_owned),
                because: expected_because.map(str::to_owned),
                policy_digest: Some(expected_policy_digest.clone()),
            })
        );
        assert_eq!(
            view.disclosed.get("summary"),
            Some(&json!("caller-visible"))
        );
        let item_json = serde_json::to_value(&item).expect("serialize routed item");
        assert!(item_json.get("routingContext").is_none());
        assert!(!item_json.to_string().contains("\"region\""));
        assert!(!item_json.to_string().contains("\"north\""));
        assert!(!item_json.to_string().contains("\"south\""));
        let history = store
            .history(&staff, item_id, 100)
            .await
            .expect("read routed history");
        let history_json = serde_json::to_string(&history).expect("serialize routed history");
        assert!(!history_json.contains("\"region\""));
        assert!(!history_json.contains("\"north\""));
        assert!(!history_json.contains("\"south\""));
    }

    let concealed_item_id: Uuid = database
        .query_one(
            "SELECT item_id FROM casework_items WHERE subject_id=$1",
            &[&concealed.to_string()],
        )
        .await
        .expect("concealed routed item exists")
        .get(0);
    assert!(matches!(
        service
            .caller_item(
                &staff,
                concealed_item_id,
                "source-profile",
                "ephemeral-token"
            )
            .await,
        Err(ServiceError::Adapter(SourceAdapterError::Concealed))
    ));
}

#[tokio::test]
async fn startup_refuses_routing_projection_absent_from_source_metadata() {
    let (store, _) = stores().await;
    let mut project = routing_project();
    project.sources[0].requests[0].projection = vec!["unpublished-field".to_owned()];
    project.sources[0].requests[0].routing[1].when.fields = BTreeMap::from([(
        "unpublished-field".to_owned(),
        RoutingPredicate::Equals(EqualsPredicate {
            equals: json!("north"),
        }),
    )]);
    let source = Arc::new(RoutingSource {
        metadata: metadata(),
        observations: BTreeMap::new(),
        concealed: BTreeSet::new(),
    });
    assert!(matches!(
        CaseworkService::new(store, project, [source as Arc<dyn SourceAdapter>]),
        Err(ServiceError::Configuration)
    ));
}
