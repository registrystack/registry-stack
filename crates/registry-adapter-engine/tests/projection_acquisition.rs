// SPDX-License-Identifier: Apache-2.0

use registry_adapter_core::{
    AdapterPack, ProjectionMode, ProjectionRecord, ProjectionRequest, ProjectionResult,
};
use registry_adapter_engine::{
    artifacts::PackArtifactBytes,
    evidence::{EvidenceAcquisitionIntent, EvidenceHookFuture, EvidenceHostHooks, EvidenceLimits},
    projection::{compile_projection_pack, ProjectionError},
    replay::ReplayTranscript,
};
use serde_json::{json, Value};
use std::{collections::BTreeSet, sync::Arc};

struct Hooks;

impl EvidenceHostHooks for Hooks {
    fn before_acquisition<'a>(&'a self, _: EvidenceAcquisitionIntent) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn operation(retention: &str) -> (AdapterPack, PackArtifactBytes) {
    let schema = serde_json::to_vec(&json!({
        "type":"object",
        "additionalProperties":false,
        "properties":{"familyName":{"type":"string"}}
    }))
    .unwrap();
    let digest = registry_platform_config::sha256_uri(&schema);
    let steps = json!([{"to":{"uri":"http:source","parameters":{
        "httpMethod":"GET", "path":"/people"
    }}}]);
    let pack: AdapterPack = serde_json::from_value(json!({
        "id":"synthetic","version":"1","testedVersions":[],
        "endpoints":[{"id":"source","component":"http","authentication":{"type":"none"},"attemptTimeoutMilliseconds":1000,"maximumResponseBytes":4096}],
        "sourceRoutes":[{"id":"lookup","projection":{
            "operation":"exact","operationVersion":"1","authority":"population-register","purpose":"licensing",
            "scope":"licensing-subjects","selectorScheme":"person-number","recordKeyScheme":"person-number",
            "retention":retention,"absence":"authoritative","localDisclosure":"host-profiles",
            "fieldsSchema":{"path":"schemas/person.json","digest":digest},
            "maximumBatchKeys":3,"maximumPages":2,"maximumRows":4
        }, "steps": steps}]
    }))
    .unwrap();
    (
        pack,
        PackArtifactBytes::new([("schemas/person.json".to_owned(), schema)]),
    )
}

fn transcript(replies: Vec<Value>) -> Arc<ReplayTranscript> {
    Arc::new(ReplayTranscript::from_exchanges(
        serde_json::from_value(json!([{"type":"endpoint","endpoint":"source"}])).unwrap(),
        serde_json::from_value(json!(replies)).unwrap(),
    ))
}

fn exact_reply(record: Value, no_store: bool) -> Value {
    let mut response = json!({"status":200,"body":{"type":"exact","record":record}});
    if no_store {
        response["headers"] = json!({"Cache-Control":"private, NO-STORE"});
    }
    json!({"request":{"endpoint":"source","method":"GET","path":"/people"},"response":response})
}

async fn exact(
    mode: ProjectionMode,
    retention: &str,
    exchanges: Arc<ReplayTranscript>,
) -> Result<ProjectionResult, ProjectionError> {
    let (pack, artifacts) = operation(retention);
    let program = compile_projection_pack(&pack, "lookup", &artifacts, EvidenceLimits::default())
        .unwrap()
        .bind_replay(exchanges)
        .unwrap();
    program
        .acquire(
            Arc::new(Hooks),
            mode,
            ProjectionRequest::Exact {
                key: "person-7".to_owned(),
            },
            &BTreeSet::from(["familyName".to_owned()]),
        )
        .await
}

#[tokio::test]
async fn governed_retention_and_raw_response_restrictions_are_independent() {
    let no_call = transcript(vec![]);
    assert!(matches!(
        exact(ProjectionMode::Indexed, "live-only", Arc::clone(&no_call)).await,
        Err(ProjectionError::RetentionRefused)
    ));
    no_call.finish().unwrap();

    let record = json!({"outcome":"present","key":"person-7","fields":{"familyName":"Lee"}});
    let protected = transcript(vec![exact_reply(record.clone(), true)]);
    assert!(matches!(
        exact(ProjectionMode::Indexed, "retain", Arc::clone(&protected)).await,
        Err(ProjectionError::NoStore)
    ));
    protected.finish().unwrap();

    let live = transcript(vec![exact_reply(record, true)]);
    assert!(matches!(
        exact(ProjectionMode::Live, "live-only", Arc::clone(&live)).await,
        Ok(ProjectionResult::Exact {
            record: ProjectionRecord::Present { .. }
        })
    ));
    live.finish().unwrap();
}

#[tokio::test]
async fn a_present_record_must_include_every_requested_field() {
    let response = transcript(vec![exact_reply(
        json!({"outcome": "present", "key": "person-7", "fields": {}}),
        false,
    )]);
    assert!(matches!(
        exact(ProjectionMode::Indexed, "retain", Arc::clone(&response)).await,
        Err(ProjectionError::InvalidResult)
    ));
    response.finish().unwrap();
}

#[tokio::test]
async fn keyed_absence_is_distinct_from_ambiguous_or_wrong_identity() {
    let absence = transcript(vec![exact_reply(
        json!({"outcome":"authoritative-absent","key":"person-7"}),
        false,
    )]);
    assert!(matches!(
        exact(ProjectionMode::Indexed, "retain", Arc::clone(&absence)).await,
        Ok(ProjectionResult::Exact {
            record: ProjectionRecord::AuthoritativeAbsent { .. }
        })
    ));
    absence.finish().unwrap();

    for result in [
        json!({"outcome":"present","key":"person-8","fields":{"familyName":"Wrong"}}),
        json!({"outcome":"present","key":"person-7","fields":{"rawSecret":"canary"}}),
    ] {
        let exchange = transcript(vec![exact_reply(result, false)]);
        assert!(matches!(
            exact(ProjectionMode::Indexed, "retain", Arc::clone(&exchange)).await,
            Err(ProjectionError::InvalidResult)
        ));
        exchange.finish().unwrap();
    }
}

fn maintained_pack() -> (AdapterPack, PackArtifactBytes) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/examples/external-projections");
    let pack: AdapterPack = registry_platform_yaml::Reader::new("pack.yaml")
        .decode(
            &std::fs::read(root.join("pack.yaml")).unwrap(),
            &registry_platform_yaml::Expect::one(&registry_platform_yaml::FormatSpec {
                kind: registry_adapter_core::ADAPTER_PACK_KIND,
                envelope: registry_platform_yaml::EnvelopeRule::ApiVersionKind {
                    api_versions: &[registry_platform_yaml::ApiVersion::current(
                        registry_adapter_core::ADAPTER_PACK_API_VERSION,
                    )],
                    retired_api_versions: &[],
                },
                removed_keys: &[],
            }),
        )
        .unwrap()
        .value;
    assert_eq!(registry_adapter_core::check_pack(&pack), vec![]);
    let artifacts = PackArtifactBytes::new(
        [
            "schemas/person.json",
            "schemas/holding.json",
            "scripts/projection.rhai",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), std::fs::read(root.join(name)).unwrap())),
    );
    (pack, artifacts)
}

async fn acquire_fixture(
    route: &str,
    request: ProjectionRequest,
    fields: &[&str],
    records: Vec<Value>,
    limits: EvidenceLimits,
) -> Result<ProjectionResult, ProjectionError> {
    let (pack, artifacts) = maintained_pack();
    let replay = Arc::new(ReplayTranscript::from_exchanges(
        serde_json::from_value(json!([{"type":"endpoint","endpoint":"synthetic-registry"}]))
            .unwrap(),
        serde_json::from_value(json!(records)).unwrap(),
    ));
    let program = compile_projection_pack(&pack, route, &artifacts, limits)
        .unwrap()
        .bind_replay(Arc::clone(&replay))
        .unwrap();
    let fields = fields.iter().map(|field| (*field).to_owned()).collect();
    let result = program
        .acquire(Arc::new(Hooks), ProjectionMode::Indexed, request, &fields)
        .await;
    replay.finish().unwrap();
    result
}

fn fixture_exchange(path: &str, request: Value, response: Value) -> Value {
    json!({
        "request":{"endpoint":"synthetic-registry","method":"POST","path":path,"body":request},
        "response":response
    })
}

#[tokio::test]
async fn native_batch_requires_exactly_one_outcome_for_each_requested_key() {
    let requested = json!({"type":"batch","keys":["person-7","person-8"],"fields":["family-name"]});
    let found = json!({"subject":"person-7","state":"found","properties":{"family-name":"Lee"}});
    let absent = json!({"subject":"person-8","state":"confirmed-absent"});
    for (records, accepted) in [
        (vec![found.clone(), absent.clone()], true),
        (vec![found.clone(), found.clone()], false),
        (vec![found.clone()], false),
        (
            vec![
                found,
                absent,
                json!({"subject":"outside","state":"ambiguous"}),
            ],
            false,
        ),
    ] {
        let result = acquire_fixture(
            "person-batch",
            ProjectionRequest::Batch {
                keys: vec!["person-7".to_owned(), "person-8".to_owned()],
            },
            &["family-name"],
            vec![fixture_exchange(
                "/people/batch",
                requested.clone(),
                json!({"status":200,"body":{"records":records}}),
            )],
            EvidenceLimits::default(),
        )
        .await;
        if accepted {
            let ProjectionResult::Batch { records } = result.unwrap() else {
                panic!("expected typed batch result")
            };
            assert!(matches!(records[0], ProjectionRecord::Present { .. }));
            assert!(matches!(
                records[1],
                ProjectionRecord::AuthoritativeAbsent { .. }
            ));
        } else {
            assert!(matches!(result, Err(ProjectionError::InvalidResult)));
        }
    }
}

fn holdings_page(cursor: Option<&str>, status: u16, page: Value, no_store: bool) -> Value {
    let mut request =
        json!({"type":"by-parent","parentKey":"business-1","fields":["shareholder-type"]});
    if let Some(cursor) = cursor {
        request["cursor"] = json!(cursor);
    }
    let mut response = json!({"status":status,"body":page});
    if no_store {
        response["headers"] = json!({"cache-control":"no-store"});
    }
    fixture_exchange("/holdings/by-business", request, response)
}

async fn holdings(
    exchanges: Vec<Value>,
    limits: EvidenceLimits,
) -> Result<ProjectionResult, ProjectionError> {
    acquire_fixture(
        "holdings-by-business",
        ProjectionRequest::ByParent {
            parent_key: "business-1".to_owned(),
        },
        &["shareholder-type"],
        exchanges,
        limits,
    )
    .await
}

#[tokio::test]
async fn a_collection_is_released_only_as_one_complete_parent_snapshot() {
    let first = json!({
        "state":"snapshot","business":"business-1","snapshotId":"snapshot-a","finished":false,"next":"page-2",
        "items":[{"holding":"holding-1","business":"business-1","properties":{"shareholder-type":"person"}}]
    });
    let last = json!({
        "state":"snapshot","business":"business-1","snapshotId":"snapshot-a","finished":true,
        "items":[{"holding":"holding-2","business":"business-1","properties":{"shareholder-type":"business"}}]
    });
    let first_page = holdings_page(None, 200, first.clone(), false);
    let last_page = holdings_page(Some("page-2"), 200, last.clone(), false);
    let result = holdings(
        vec![first_page.clone(), last_page.clone()],
        EvidenceLimits::default(),
    )
    .await
    .unwrap();
    let ProjectionResult::ByParent { rows, .. } = result else {
        panic!("expected complete typed snapshot")
    };
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].fields["shareholder-type"], "business");

    let empty = json!({"state":"snapshot","business":"business-1","snapshotId":"empty","finished":true,"items":[]});
    assert!(matches!(
        holdings(vec![holdings_page(None, 200, empty, false)], EvidenceLimits::default()).await,
        Ok(ProjectionResult::ByParent {rows, ..}) if rows.is_empty()
    ));

    let interrupted = holdings_page(Some("page-2"), 403, json!({"state":"denied"}), false);
    assert!(matches!(
        holdings(
            vec![first_page.clone(), interrupted],
            EvidenceLimits::default()
        )
        .await,
        Err(ProjectionError::Unavailable)
    ));
    let blocked = holdings_page(None, 200, first, true);
    assert!(matches!(
        holdings(vec![blocked], EvidenceLimits::default()).await,
        Err(ProjectionError::NoStore)
    ));

    let mut wrong_snapshot = last.clone();
    wrong_snapshot["snapshotId"] = json!("snapshot-b");
    let mut wrong_parent = last.clone();
    wrong_parent["items"][0]["business"] = json!("business-2");
    let mut duplicate = last;
    duplicate["items"][0]["holding"] = json!("holding-1");
    for malformed in [wrong_snapshot, wrong_parent, duplicate] {
        assert!(matches!(
            holdings(
                vec![
                    first_page.clone(),
                    holdings_page(Some("page-2"), 200, malformed, false)
                ],
                EvidenceLimits::default()
            )
            .await,
            Err(ProjectionError::InvalidResult)
        ));
    }
    assert!(matches!(
        holdings(
            vec![first_page],
            EvidenceLimits::try_new(1, 1000, 4096).unwrap()
        )
        .await,
        Err(ProjectionError::Unavailable)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn live_source_sees_the_service_identity_and_only_the_requested_fields() {
    use registry_adapter_core::{AdapterEndpointBindings, EvidenceConnectionPolicy};
    use registry_adapter_engine::evidence::EvidenceRuntimeBindings;
    use registry_platform_config::{SecretProvider, SecretResolver};
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const SYNTHETIC_CREDENTIAL: &str = "fixture-projection-service-identity";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let source = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = Vec::new();
        let mut chunk = [0; 512];
        let (header_length, content_length) = loop {
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0 && buffer.len() + count <= 8192);
            buffer.extend_from_slice(&chunk[..count]);
            if let Some(end) = buffer.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let header = std::str::from_utf8(&buffer[..end]).unwrap();
                assert!(header
                    .lines()
                    .next()
                    .unwrap()
                    .starts_with("POST /people/batch "));
                let headers: std::collections::BTreeMap<_, _> = header
                    .lines()
                    .skip(1)
                    .map(|line| line.split_once(':').unwrap())
                    .map(|(name, value)| (name.to_ascii_lowercase(), value.trim()))
                    .collect();
                assert!(headers.get("x-registry-service-key") == Some(&SYNTHETIC_CREDENTIAL));
                break (end + 4, headers["content-length"].parse::<usize>().unwrap());
            }
        };
        assert!(header_length + content_length <= 8192);
        while buffer.len() < header_length + content_length {
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0 && buffer.len() + count <= 8192);
            buffer.extend_from_slice(&chunk[..count]);
        }
        let body: Value =
            serde_json::from_slice(&buffer[header_length..header_length + content_length]).unwrap();
        assert_eq!(
            body,
            json!({"type":"batch","keys":["person-7"],"fields":["family-name"]})
        );
        let response = br#"{"records":[{"subject":"person-7","state":"found","properties":{"family-name":"Lee"}}]}"#;
        socket.write_all(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: private\r\nCache-Control: NO-STORE\r\nConnection: close\r\n\r\n",
            response.len()
        ).as_bytes()).await.unwrap();
        socket.write_all(response).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let secret = root.path().join("service-key");
    std::fs::write(&secret, SYNTHETIC_CREDENTIAL).unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let runtime = EvidenceRuntimeBindings::new(
        serde_json::from_value::<AdapterEndpointBindings>(json!({
            "id":"synthetic-connection",
            "endpoints":[{
                "endpoint":"synthetic-registry","baseUrl":origin,
                "credential":{"type":"static-api-key","valueRef":"secret:file/service-key"}
            }]
        }))
        .unwrap(),
        SecretResolver::new([SecretProvider::File], root.path()).unwrap(),
    );
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"synthetic-registry","baseUrl":origin,"clientIdentity":"forbidden",
        "authentication":{"type":"static-api-key"}
    }))
    .unwrap();
    let (pack, artifacts) = maintained_pack();
    let program =
        compile_projection_pack(&pack, "person-batch", &artifacts, EvidenceLimits::default())
            .unwrap()
            .bind_live(&runtime, "synthetic-connection", &[policy])
            .unwrap();
    let result = program
        .acquire(
            Arc::new(Hooks),
            ProjectionMode::Indexed,
            ProjectionRequest::Batch {
                keys: vec!["person-7".to_owned()],
            },
            &BTreeSet::from(["family-name".to_owned()]),
        )
        .await;
    assert!(
        matches!(result, Err(ProjectionError::NoStore)),
        "{result:?}"
    );
    tokio::time::timeout(Duration::from_secs(2), source)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_audit_delay_cannot_start_source_io_after_the_grant_deadline() {
    struct SlowAudit;
    impl EvidenceHostHooks for SlowAudit {
        fn before_acquisition<'a>(
            &'a self,
            _: EvidenceAcquisitionIntent,
        ) -> EvidenceHookFuture<'a> {
            Box::pin(async {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                Ok(())
            })
        }
    }

    let exchanges = transcript(vec![]);
    let (pack, artifacts) = operation("retain");
    let program = compile_projection_pack(&pack, "lookup", &artifacts, EvidenceLimits::default())
        .unwrap()
        .bind_replay(Arc::clone(&exchanges))
        .unwrap();
    let result = program
        .acquire_until(
            Arc::new(SlowAudit),
            ProjectionMode::Indexed,
            ProjectionRequest::Exact {
                key: "person-7".to_owned(),
            },
            &BTreeSet::from(["familyName".to_owned()]),
            Some(tokio::time::Instant::now() + std::time::Duration::from_secs(1)),
        )
        .await;
    assert!(matches!(result, Err(ProjectionError::Unavailable)));
    exchanges.finish().unwrap();
}
