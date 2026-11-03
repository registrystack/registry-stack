// SPDX-License-Identifier: Apache-2.0

//! Every maintained synthetic OpenCRVS fixture through the actual offline
//! route interpreter. This proves engine execution only, never a live
//! OpenCRVS exchange.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use registry_adapter::engine::{
    artifacts::PackArtifactBytes,
    evidence::{
        compile_evidence_pack, EvidenceAcquisitionIntent, EvidenceHookFuture, EvidenceHostHooks,
        EvidenceLimits, EvidenceLookup,
    },
    replay::ReplayTranscript,
    scripts::ScriptSet,
};
use registry_adapter::replay_serve as replay;
use registry_adapter_core::{
    check_job_boundaries, check_pack, check_routes, AdapterFixture, AdapterPack, AdapterProfile,
    AdapterProject, ADAPTER_FIXTURE_API_VERSION, ADAPTER_FIXTURE_KIND, ADAPTER_PACK_API_VERSION,
    ADAPTER_PACK_KIND, ADAPTER_PROFILE_API_VERSION, ADAPTER_PROFILE_KIND,
    ADAPTER_PROJECT_API_VERSION, ADAPTER_PROJECT_KIND,
};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

const PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROJECT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

const PROFILE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROFILE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROFILE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

const PACK_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PACK_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PACK_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

const FIXTURE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_FIXTURE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_FIXTURE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn authored<T: DeserializeOwned>(path: &Path, format: &FormatSpec<'static>) -> T {
    let bytes = std::fs::read(path).expect("the authored document is readable");
    Reader::new(path.display().to_string())
        .decode::<T>(&bytes, &Expect::one(format))
        .expect("the authored document passes the platform YAML reader")
        .value
}

fn opencrvs_pack() -> (PathBuf, AdapterPack) {
    let path = repository().join("products/adapter/packs/opencrvs-events/pack.yaml");
    let pack = authored(&path, &PACK_FORMAT);
    (path, pack)
}

fn opencrvs_artifacts(directory: &Path) -> PackArtifactBytes {
    PackArtifactBytes::new(
        [
            "schemas/evidence-inputs.json",
            "schemas/evidence-adult-facts.json",
            "schemas/evidence-adult-provider.json",
            "schemas/evidence-parents-facts.json",
            "schemas/evidence-parents-provider.json",
            "scripts/get-query.rhai",
            "scripts/evidence.rhai",
        ]
        .into_iter()
        .map(|path| {
            (
                path.to_owned(),
                std::fs::read(directory.join(path)).expect("the pack artifact is readable"),
            )
        }),
    )
}

fn registered_event_query(tracking_id: &str) -> Value {
    json!({
        "query": {
            "type": "and",
            "clauses": [{
                "eventType": "birth",
                "status": { "type": "exact", "term": "REGISTERED" },
                "trackingId": { "type": "exact", "term": tracking_id }
            }]
        },
        "limit": 2,
        "offset": 0
    })
}

struct AllowAcquisition;

impl EvidenceHostHooks for AllowAcquisition {
    fn before_acquisition<'a>(
        &'a self,
        _intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn source_transcript(response: Value) -> Arc<ReplayTranscript> {
    Arc::new(ReplayTranscript::from_exchanges(
        serde_json::from_value(json!([
            { "type": "endpoint", "endpoint": "events" },
            { "type": "token-endpoint", "endpoint": "events" }
        ]))
        .expect("closed replay intercepts"),
        serde_json::from_value(json!([
            {
                "request": {
                    "endpoint": "events",
                    "tokenRequest": true,
                    "method": "POST",
                    "path": "/token"
                },
                "response": {
                    "status": 200,
                    "body": {
                        "access_token": "synthetic-opencrvs-replay-token",
                        "token_type": "Bearer",
                        "expires_in": 300
                    }
                }
            },
            {
                "request": {
                    "endpoint": "events",
                    "method": "POST",
                    "path": "/events/search",
                    "headers": { "accept": "application/json" },
                    "body": registered_event_query("TRACKING-SYNTHETIC-001")
                },
                "response": { "status": 200, "body": response }
            }
        ]))
        .expect("closed replay exchanges"),
    ))
}

#[test]
fn maintained_opencrvs_pack_passes_authoring_checks() {
    let (_, pack) = opencrvs_pack();
    let project = authored(
        &repository().join("products/adapter/examples/opencrvs-events/project.yaml"),
        &PROJECT_FORMAT,
    );
    let findings = check_pack(&pack)
        .into_iter()
        .chain(check_routes(&pack, &project))
        .chain(check_job_boundaries(&pack, &project))
        .collect::<Vec<_>>();
    assert!(
        findings.is_empty(),
        "maintained pack findings: {findings:?}"
    );
}

#[test]
fn facade_and_evidence_queries_have_the_same_exact_shape() {
    let (pack_path, pack) = opencrvs_pack();
    let mut scripts = ScriptSet::default();
    for entrypoint in ["get_query", "source_query"] {
        scripts
            .add(
                &pack,
                pack_path.parent().expect("the pack directory"),
                "scripts/get-query.rhai",
                entrypoint,
            )
            .expect("the query entrypoint compiles under its pinned digest");
    }
    let code_maps = Arc::new(BTreeMap::new());
    let facade = scripts
        .call(
            &code_maps,
            "scripts/get-query.rhai",
            "get_query",
            &json!({
                "body": null,
                "headers": { "recordid": "TRACKING-SYNTHETIC-001" },
                "properties": { "opencrvsEventType": "birth" }
            }),
        )
        .expect("the facade query runs");
    let evidence = scripts
        .call(
            &code_maps,
            "scripts/get-query.rhai",
            "source_query",
            &json!({
                "body": { "trackingId": "TRACKING-SYNTHETIC-001" },
                "headers": {},
                "properties": { "opencrvsEventType": "birth" }
            }),
        )
        .expect("the Evidence query runs");
    assert_eq!(facade, registered_event_query("TRACKING-SYNTHETIC-001"));
    assert_eq!(evidence, facade);
}

async fn replay_source_route(route: &str, response: Value) -> EvidenceLookup {
    let (pack_path, pack) = opencrvs_pack();
    let checked = compile_evidence_pack(
        &pack,
        route,
        &opencrvs_artifacts(pack_path.parent().expect("the pack directory")),
        EvidenceLimits::default(),
    )
    .expect("the reviewed source route compiles");
    let transcript = source_transcript(response);
    let program = checked
        .bind_replay(Arc::clone(&transcript))
        .expect("the source route binds to sealed replay");
    let acquisition = program
        .begin_acquisition(Arc::new(AllowAcquisition))
        .await
        .expect("the synthetic acquisition starts");
    let lookup = program
        .execute(
            &acquisition,
            json!({ "trackingId": "TRACKING-SYNTHETIC-001" }),
        )
        .await
        .expect("the source route returns schema-valid facts");
    transcript
        .finish()
        .expect("the route consumed the exact body and Accept-only headers");
    lookup
}

#[tokio::test]
async fn evidence_source_routes_use_body_inputs_and_project_minimal_facts() {
    let date = replay_source_route(
        "evidence-birth-date",
        json!({
            "total": 1,
            "results": [{
                "type": "birth",
                "status": "REGISTERED",
                "trackingId": "TRACKING-SYNTHETIC-001",
                "dateOfEvent": "2000-01-01",
                "declaration": { "unrelated": "SOURCE-UNRELATED-CANARY" }
            }]
        }),
    )
    .await;
    assert_eq!(
        date,
        EvidenceLookup::Matched {
            facts: json!({
                "record_tracking_id": "TRACKING-SYNTHETIC-001",
                "date_of_birth": "2000-01-01"
            })
        }
    );

    let parents = replay_source_route(
        "evidence-birth-parents",
        json!({
            "total": 1,
            "results": [{
                "type": "birth",
                "status": "REGISTERED",
                "trackingId": "TRACKING-SYNTHETIC-001",
                "declaration": {
                    "mother.personReference": "PERSON-SYNTHETIC-A",
                    "father.personReference": "PERSON-SYNTHETIC-B",
                    "unrelated.field": "SOURCE-UNRELATED-CANARY"
                }
            }]
        }),
    )
    .await;
    assert_eq!(
        parents,
        EvidenceLookup::Matched {
            facts: json!({
                "record_tracking_id": "TRACKING-SYNTHETIC-001",
                "parent_references": ["PERSON-SYNTHETIC-A", "PERSON-SYNTHETIC-B"],
                "reference_namespace": "urn:gov:example:opencrvs:person",
                "relationship_set_contract": "urn:gov:example:opencrvs:registered-parent-set:v1",
                "relationship_set_complete": true
            })
        }
    );
}

#[tokio::test]
async fn all_maintained_opencrvs_fixtures_execute_in_the_engine() {
    let root = repository();
    let (pack_path, pack) = opencrvs_pack();
    let profile: AdapterProfile = authored(
        &root.join("products/adapter/profiles/breg-records/profile.yaml"),
        &PROFILE_FORMAT,
    );
    let project: AdapterProject = authored(
        &root.join("products/adapter/examples/opencrvs-events/project.yaml"),
        &PROJECT_FORMAT,
    );
    let mut fixtures = std::fs::read_dir(root.join("products/adapter/fixtures/opencrvs-events"))
        .expect("the fixture directory is readable")
        .map(|entry| entry.expect("a fixture entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .collect::<Vec<_>>();
    fixtures.sort();

    let mut replayed = 0usize;
    for fixture_path in fixtures {
        let fixture: AdapterFixture = authored(&fixture_path, &FIXTURE_FORMAT);
        for entry_index in 0..fixture.entries.len() {
            replay::run(
                &project,
                &profile,
                &pack,
                pack_path.parent().expect("the pack directory"),
                &fixture,
                entry_index,
            )
            .await
            .unwrap_or_else(|failure| {
                panic!(
                    "{} failed actual engine replay: {failure:?}",
                    fixture_path.display()
                )
            });
            replayed += 1;
        }
    }
    assert_eq!(replayed, 10, "every maintained fixture entry ran");
}
