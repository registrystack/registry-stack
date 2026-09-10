// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use registry_casework::{
    router, CaseworkAuthenticator, CaseworkService, DatabaseConfig, HttpState, HumanIdentityConfig,
    PostgresStore,
};
use registry_casework_client::{
    CaseworkAuth, CaseworkClient, CaseworkClientConfig, CaseworkClientError, CaseworkProblemCode,
};
use registry_casework_core::{
    BootstrapDirectoryRequest, CaseworkAction, CaseworkProject, HostedCancelRequest,
    HostedCreateRequest, HostedDecisionRequest, HostedHistoryKind, HostedNoteRequest,
    HostedPageQuery, HostedTerminalQuery, HostedTerminalState, InboxView, IssuerPrincipal,
    ListWorkItemsQuery, SourceAdapter, WorkItem,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_httputil::{client::BearerToken, FetchUrlPolicy};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::json;

const DATABASE_ENV: &str = "CASEWORK_HOSTED_ACCEPTANCE_DATABASE_URL";
const SCHEMA_DATABASE_ENV: &str = "CASEWORK_HOSTED_ACCEPTANCE_SCHEMA_URL";
const AUDIENCE: &str = "urn:test:casework-standalone";

fn token(idp: &MockIdp, subject: &str, profile: &str, human: bool) -> BearerToken {
    BearerToken::new(idp.mint_token(json!({
        "aud": AUDIENCE,
        "sub": subject,
        "scope": format!("casework:{profile}"),
        "registry_actor_kind": if human { "human" } else { "service" }
    })))
    .expect("synthetic test token")
}

fn action(item: &WorkItem, operation: &str) -> CaseworkAction {
    item.actions
        .iter()
        .find(|action| action.operation == operation)
        .expect("the service advertises this action")
        .clone()
}

/// One complete client journey over real HTTP and PostgreSQL, with no source
/// adapter registered. Storage-specific races and retention use separate tests.
#[tokio::test]
async fn ten_items_two_create_retries_and_one_terminal_result_without_breg() {
    let database_url = std::env::var(DATABASE_ENV).expect("dedicated acceptance database URL");
    let (schema_admin, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
        .await
        .expect("connect to acceptance database");
    let database_driver = tokio::spawn(connection);
    let schema = format!("hosted_acceptance_{}", uuid::Uuid::new_v4().simple());
    schema_admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if database_url.contains('?') { '&' } else { '?' };
    // This binary has one current-thread test; configure its private schema
    // before starting any HTTP fixture or connection pool.
    std::env::set_var(
        SCHEMA_DATABASE_ENV,
        format!("{database_url}{separator}options=-csearch_path%3D{schema}"),
    );
    let resolver = SecretResolver::new([SecretProvider::Environment], "/").unwrap();
    let database = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{SCHEMA_DATABASE_ENV}"),
        migration_url_ref: format!("secret:env/{SCHEMA_DATABASE_ENV}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let migration = PostgresStore::connect_migration(&database, &resolver).unwrap();
    migration.migrate().await.unwrap();
    let store = PostgresStore::connect_runtime(&database, &resolver).unwrap();
    let project: CaseworkProject = serde_norway::from_str(include_str!(
        "../../../products/casework/examples/standalone-decision/casework.yaml"
    ))
    .unwrap();
    project.check().unwrap();
    assert!(project.sources.is_empty());
    let queue = project.hosted_kinds[0].queue.clone();
    let kind = project.hosted_kinds[0].id.clone();
    let policy_digest = project.hosted_kinds[0].policy_digest().unwrap();
    let idp = MockIdp::start().await;
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let authenticator = Arc::new(CaseworkAuthenticator::new(
        &project,
        oidc_verifier_config(idp.issuer(), vec![AUDIENCE.into()]),
        keys,
        HumanIdentityConfig::default(),
    ));
    let service = CaseworkService::new(
        store,
        project.clone(),
        std::iter::empty::<Arc<dyn SourceAdapter>>(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = router(HttpState {
        service,
        authenticator,
        project: Arc::new(project),
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = CaseworkClient::new(CaseworkClientConfig::new(
        format!("http://{address}").parse().unwrap(),
    ))
    .unwrap();
    let admin = token(&idp, "administrator", "admin", true);
    let staff = token(&idp, "staff", "staff", true);
    let supervisor = token(&idp, "supervisor", "supervisor", true);
    let requester = token(&idp, "requester", "request", false);
    let outsider = token(&idp, "other-requester", "request", false);
    client
        .bootstrap_directory(
            CaseworkAuth::new(&admin, "administrator"),
            0,
            "bootstrap",
            &BootstrapDirectoryRequest {
                team_id: "deciding-team".into(),
                queue_id: queue.clone(),
                staff: vec![IssuerPrincipal {
                    issuer: idp.issuer(),
                    subject: "staff".into(),
                }],
                supervisors: vec![IssuerPrincipal {
                    issuer: idp.issuer(),
                    subject: "supervisor".into(),
                }],
            },
        )
        .await
        .unwrap();

    let mut created = Vec::new();
    for number in 0..10 {
        let request = HostedCreateRequest {
            kind: kind.clone(),
            requester_reference: format!("reference-{number}"),
            display: json!({"summary": format!("Synthetic item {number}"), "reference": format!("REF-{number}")}),
        };
        let key = format!("create-{number}");
        let item = client
            .create_hosted_item(CaseworkAuth::new(&requester, "requester"), &key, &request)
            .await
            .unwrap()
            .value;
        assert_eq!(item.kind_policy_digest, policy_digest);
        if number < 2 {
            let replay = client
                .create_hosted_item(CaseworkAuth::new(&requester, "requester"), &key, &request)
                .await
                .unwrap()
                .value;
            assert_eq!(replay, item);
        }
        created.push(item);
    }
    client
        .add_hosted_note(
            CaseworkAuth::new(&requester, "requester"),
            created[0].item_id,
            created[0].revision,
            "add-requester-note",
            &HostedNoteRequest {
                note: "Requester supplied clarification".into(),
            },
        )
        .await
        .unwrap();
    let notes = client
        .requester_hosted_notes(
            CaseworkAuth::new(&requester, "requester"),
            created[0].item_id,
            &HostedPageQuery::default(),
        )
        .await
        .unwrap()
        .value;
    assert_eq!(notes.items.len(), 1);
    assert_eq!(notes.items[0].note, "Requester supplied clarification");
    assert!(matches!(
        client
            .requester_hosted_notes(
                CaseworkAuth::new(&outsider, "requester"),
                created[0].item_id,
                &HostedPageQuery::default(),
            )
            .await,
        Err(CaseworkClientError::Problem { status: 404, .. })
    ));
    assert!(matches!(
        client
            .get_hosted_item(
                CaseworkAuth::new(&outsider, "requester"),
                created[0].item_id
            )
            .await,
        Err(CaseworkClientError::Problem {
            status: 404,
            code: CaseworkProblemCode::WorkItemNotVisible,
            ..
        })
    ));
    assert!(matches!(
        client
            .get_hosted_work_item(
                CaseworkAuth::new(&requester, "requester"),
                created[0].item_id
            )
            .await,
        Err(CaseworkClientError::Problem {
            status: 403 | 404,
            ..
        })
    ));
    let inbox = client
        .list_hosted_work_items(
            CaseworkAuth::new(&staff, "staff"),
            &ListWorkItemsQuery {
                view: InboxView::MyTeams,
                queue: Some(queue),
                cursor: None,
                limit: Some(25),
            },
        )
        .await
        .unwrap()
        .value;
    assert_eq!(inbox.items.len(), 10);

    for (number, item) in inbox.items.iter().enumerate() {
        let claim = client
            .claim_hosted_work_item(
                CaseworkAuth::new(&staff, "staff"),
                &action(item, "claim"),
                &format!("claim-{number}"),
            )
            .await
            .unwrap()
            .value
            .item;
        if number == 8 {
            client
                .cancel_hosted_item(
                    CaseworkAuth::new(&requester, "requester"),
                    item.item_id,
                    claim.revision,
                    "cancel-withdrawn",
                    &HostedCancelRequest {
                        reason: "Requester withdrew".into(),
                    },
                )
                .await
                .unwrap();
            continue;
        }
        let outcome = if number == 0 { "rejected" } else { "confirmed" };
        let decision_action = action(&claim, outcome);
        let decision = HostedDecisionRequest {
            outcome: outcome.into(),
            reason: Some("Staff-only decision rationale".into()),
        };
        if number == 0 {
            let missing_reason = HostedDecisionRequest {
                outcome: outcome.into(),
                reason: None,
            };
            let refused = client
                .decide_hosted_work_item(
                    CaseworkAuth::new(&staff, "staff"),
                    &decision_action,
                    "missing-reason",
                    &missing_reason,
                )
                .await
                .expect_err("the declared rejection reason is required");
            assert!(matches!(refused, CaseworkClientError::Problem {
                status: 400, code: CaseworkProblemCode::RequestInvalid,
                validation: Some(ref field), ..
            } if field.path == "$.reason"));
        }
        if number == 9 {
            let current = client
                .get_hosted_item(CaseworkAuth::new(&requester, "requester"), item.item_id)
                .await
                .unwrap()
                .value;
            let cancellation = HostedCancelRequest {
                reason: "Requester withdrew".into(),
            };
            let (decided, cancelled) = tokio::join!(
                client.decide_hosted_work_item(
                    CaseworkAuth::new(&staff, "staff"),
                    &decision_action,
                    "race-decide",
                    &decision
                ),
                client.cancel_hosted_item(
                    CaseworkAuth::new(&requester, "requester"),
                    item.item_id,
                    current.revision,
                    "race-cancel",
                    &cancellation
                ),
            );
            assert_ne!(
                decided.is_ok(),
                cancelled.is_ok(),
                "exactly one terminal transition commits"
            );
            let refused = decided.err().or_else(|| cancelled.err()).unwrap();
            assert!(matches!(
                refused,
                CaseworkClientError::Problem {
                    status: 412,
                    code: CaseworkProblemCode::PreconditionFailed,
                    ..
                }
            ));
        } else {
            client
                .decide_hosted_work_item(
                    CaseworkAuth::new(&staff, "staff"),
                    &decision_action,
                    &format!("decide-{number}"),
                    &decision,
                )
                .await
                .unwrap();
        }
    }
    let results = client
        .hosted_terminal_items(
            CaseworkAuth::new(&requester, "requester"),
            &HostedTerminalQuery {
                cursor: None,
                limit: Some(25),
            },
        )
        .await
        .unwrap()
        .value;
    assert_eq!(results.items.len(), 10);
    let ids: std::collections::BTreeSet<_> =
        results.items.iter().map(|result| result.item_id).collect();
    assert_eq!(ids.len(), 10);
    let serialized = serde_json::to_string(&results).unwrap();
    assert!(!serialized.contains("Staff-only decision rationale"));
    assert!(!serialized.contains(&idp.issuer()));
    assert!(!serialized.contains("\"staff\""));
    let history = client
        .hosted_work_item_history(
            CaseworkAuth::new(&staff, "staff"),
            created[0].item_id,
            &HostedPageQuery::default(),
        )
        .await
        .unwrap()
        .value;
    for kind in [
        HostedHistoryKind::Created,
        HostedHistoryKind::NoteAdded,
        HostedHistoryKind::Claimed,
        HostedHistoryKind::Completed,
    ] {
        assert!(history.items.iter().any(|entry| entry.kind == kind));
    }
    let history_json = serde_json::to_string(&history).unwrap();
    assert!(!history_json.contains(&idp.issuer()));
    assert!(history_json.contains("Staff-only decision rationale"));
    let decided = results
        .items
        .iter()
        .find(|result| matches!(result.terminal, HostedTerminalState::Completed { .. }))
        .unwrap();
    let accountability = client
        .hosted_accountability_record(
            CaseworkAuth::new(&supervisor, "supervisor"),
            decided.event_id,
        )
        .await
        .unwrap()
        .value;
    assert_eq!(accountability.actor.subject, "staff");
    assert_eq!(
        accountability.reason.as_deref(),
        Some("Staff-only decision rationale")
    );
    assert!(matches!(
        client
            .hosted_accountability_record(
                CaseworkAuth::new(&admin, "administrator"),
                decided.event_id,
            )
            .await,
        Err(CaseworkClientError::Problem {
            status: 403 | 404,
            ..
        })
    ));
    assert!(matches!(
        client
            .hosted_accountability_record(
                CaseworkAuth::new(&requester, "requester"),
                decided.event_id,
            )
            .await,
        Err(CaseworkClientError::Problem {
            status: 403 | 404,
            ..
        })
    ));
    let replay = client
        .hosted_terminal_items(
            CaseworkAuth::new(&requester, "requester"),
            &HostedTerminalQuery {
                cursor: None,
                limit: Some(25),
            },
        )
        .await
        .unwrap()
        .value;
    assert_eq!(results.items, replay.items);
    let empty = client
        .hosted_terminal_items(
            CaseworkAuth::new(&outsider, "requester"),
            &HostedTerminalQuery::default(),
        )
        .await
        .unwrap()
        .value;
    assert!(empty.items.is_empty());
    if let Ok(script) = std::env::var("CASEWORK_OPENFN_SMOKE_SCRIPT") {
        // Optional local composition with the packaged OpenFn adaptor. Pass
        // synthetic credentials over stdin, never command arguments or logs.
        let input = serde_json::to_vec(&json!({
            "baseUrl": format!("http://{address}"),
            "token": idp.mint_token(json!({
                "aud": AUDIENCE,
                "sub": "openfn-requester",
                "scope": "casework:request",
                "registry_actor_kind": "service"
            })),
            "profile": "requester",
            "kind": kind
        }))
        .unwrap();
        let output = tokio::task::spawn_blocking(move || {
            use std::io::Write;
            use std::process::{Command, Stdio};

            let mut child = Command::new("node")
                .arg(script)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start installed OpenFn smoke");
            child.stdin.take().unwrap().write_all(&input).unwrap();
            child.wait_with_output().unwrap()
        })
        .await
        .unwrap();
        assert!(output.status.success(), "OpenFn composition failed");
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["terminalObserved"], true);
        assert_eq!(
            result["operations"],
            json!(["create", "read", "note", "read_notes", "cancel", "poll"])
        );
    }
    server.abort();
    let _ = server.await;
    idp.stop().await;
    schema_admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    drop(schema_admin);
    database_driver.await.unwrap().unwrap();
}
