// SPDX-License-Identifier: Apache-2.0

//! The composed governed-ingestion journey over the source-neutral core:
//! a pack with a source route, a job definition pinned to it, the job
//! checks over both, and one produced page validated against the job's
//! profile (`products/adapter/CONCEPT.md` sections 17.1 and 17.2).

use registry_adapter_core::{
    check_job, check_workspace, AdapterJob, AdapterPack, AdapterProfile, AdapterProject, ItemPage,
    Workspace,
};

const PACK: &str = r#"{
    "id": "kobo-pack",
    "version": "1",
    "testedVersions": ["1.0"],
    "endpoints": [
        { "id": "submissions", "component": "file", "authentication": { "type": "none" },
          "attemptTimeoutMilliseconds": 10000, "maximumResponseBytes": 16777216 },
        { "id": "ledger", "component": "postgres", "authentication": { "type": "none" },
          "attemptTimeoutMilliseconds": 10000, "maximumResponseBytes": 1048576,
          "queryFile": "queries/ledger.sql" }
    ],
    "queryFiles": [
        { "path": "queries/ledger.sql",
          "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
    ],
    "routes": [
        { "id": "facade-route", "from": { "uri": "direct:facadeRoute" },
          "steps": [ { "setBody": { "constant": null } } ] },
        { "id": "normalize", "from": { "uri": "direct:normalize" },
          "steps": [ { "setBody": { "jsonpath": "$.value" } } ] }
    ],
    "sourceRoutes": [
        { "id": "kobo-submissions", "scan": "ongoing", "nextRecovery": "key-deduplicated",
          "steps": [
            { "pollEnrich": {
                "uri": "file:submissions",
                "timeoutMilliseconds": 5000,
                "decoder": { "delimiter": ";", "header": true },
                "aggregationStrategy": { "type": "json-merge", "from": "page", "into": "records" }
            } },
            { "to": { "uri": "direct:normalize" } },
            { "to": { "uri": "postgres:ledger", "parameters": { "queryParameters": { "since": { "exchangeProperty": "AdapterJobCursor" } } } } }
          ] }
    ]
}"#;

const PROFILE: &str = r#"{
    "id": "case-api",
    "version": "1",
    "operations": [
        {
            "id": "cases-find",
            "method": "GET",
            "path": "/v2/cases/{type}",
            "pathParameters": ["type"],
            "recordTypeParameter": "type",
            "recordIdParameter": "type",
            "successStatus": 200,
            "responseEnvelope": "{\"cases\": {{records}}}"
        }
    ],
    "problems": [
        { "code": "cases.upstream", "status": 502, "title": "the source could not be reached",
          "classes": ["upstream", "breaker.open", "throttle.rejected", "loop.maximum-iterations-reached"] },
        { "code": "cases.mapping", "status": 422, "title": "the request or its mapping was refused",
          "classes": ["validation", "conversion.unmapped", "aggregation.duplicate"] },
        { "code": "cases.exhausted", "status": 502, "title": "the run exhausted a budget",
          "classes": ["script", "budget.exhausted"] },
        { "code": "cases.boundary", "status": 500, "title": "the facade refused the call",
          "classes": ["disclosure.violation", "egress.refused", "credential.rejected", "outcome", "facade"] }
    ],
    "problemEnvelope": "{\"family\": \"{{problemCode}}\"}"
}"#;

const PROJECT: &str = r#"{
    "project": { "id": "kobo-deployment", "version": "1" },
    "profile": {
        "id": "case-api",
        "version": "1",
        "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"
    },
    "pack": {
        "id": "kobo-pack",
        "version": "1",
        "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"
    },
    "recordTypes": [
        { "name": "case", "fields": [ { "name": "national_id", "type": "string", "required": true } ] }
    ],
    "bindings": [
        { "id": "find-cases", "operation": "cases-find", "recordType": "case",
          "route": "facade-route", "maximumUpstreamCalls": 4 }
    ]
}"#;

fn job() -> AdapterJob {
    serde_json::from_str(
        r#"{
        "apiVersion": "id.registrystack.org/formats/adapter/job/v1alpha1",
        "kind": "AdapterJob",
        "job": { "id": "kobo-daily", "version": "1" },
        "source": {
            "pack": {
                "id": "kobo-pack",
                "version": "1",
                "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"
            },
            "route": "kobo-submissions"
        },
        "profile": {
            "pageDeadlineMilliseconds": 300000,
            "maximumResponseBytes": 16777216,
            "maximumPageItems": 500,
            "maximumPageBytes": 1048576,
            "read": {
                "maximumFileBytes": 1073741824,
                "maximumRowBytes": 1048576,
                "maximumFieldBytes": 65536,
                "maximumRowsPerPage": 500
            }
        }
    }"#,
    )
    .expect("job")
}

fn pack() -> AdapterPack {
    serde_json::from_str(PACK).expect("pack")
}

fn profile() -> AdapterProfile {
    serde_json::from_str(PROFILE).expect("profile")
}

fn project() -> AdapterProject {
    serde_json::from_str(PROJECT).expect("project")
}

fn codes(findings: &[registry_platform_yaml::Diagnostic]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| finding.code.clone())
        .collect()
}

/// The composed journey: the workspace with the bound facade route, the
/// shared normalize route, and the source route checks clean; the job over
/// the same pack checks clean; and one produced page validates against the
/// job profile and round-trips.
#[test]
fn the_governed_ingestion_journey_checks_clean_end_to_end() {
    let pack = pack();
    let profile = profile();
    let project = project();
    let ws = Workspace {
        profile: &profile,
        pack: &pack,
        project: &project,
        runtime: None,
        fixtures: &[],
    };
    let workspace_findings = check_workspace(&ws);
    assert!(
        workspace_findings.is_empty(),
        "the composed workspace checks clean: {:?}",
        codes(&workspace_findings)
    );

    let job = job();
    let job_findings = check_job(&job, &pack);
    assert!(
        job_findings.is_empty(),
        "the job checks clean over its pinned pack: {:?}",
        codes(&job_findings)
    );

    // One produced page: a leading-zero identifier stays text, the
    // revision rides beside it, and the cursor carries the read position.
    let page = ItemPage::from_value(
        &serde_json::json!({
            "items": [
                { "key": "region/form/045", "revision": "42",
                  "value": { "answers": { "age": "045" } } }
            ],
            "next": { "digest": "sha256:ab", "position": 512 }
        }),
        &job.profile,
    )
    .expect("a sound page");
    let back = ItemPage::from_value(&page.to_value(), &job.profile).expect("round trip");
    assert_eq!(back, page);
}

/// A job pinned to a source route its pack does not carry, or a profile
/// tighter than an endpoint the route reaches, refuses beside the workspace
/// checks: the facade stays clean while the job side refuses.
#[test]
fn a_defective_job_refuses_beside_a_clean_workspace() {
    let pack = pack();
    let profile = profile();
    let project = project();
    // The binding reaches an internal route, never the source route, so
    // the workspace stays clean.
    let ws = Workspace {
        profile: &profile,
        pack: &pack,
        project: &project,
        runtime: None,
        fixtures: &[],
    };
    assert!(
        check_workspace(&ws).is_empty(),
        "the facade workspace stays clean"
    );

    let mut misplaced = job();
    misplaced.source.route = "nope".to_string();
    let findings = check_job(&misplaced, &pack);
    assert_eq!(
        codes(&findings),
        vec!["adapter.job.route-unknown".to_string()],
        "an unknown source route refuses alone: {findings:?}"
    );

    let mut tight = job();
    tight.profile.maximum_response_bytes = 1_048_575;
    let findings = check_job(&tight, &pack);
    assert!(
        codes(&findings).contains(&"adapter.job.profile-endpoint-bound".to_string()),
        "a profile tighter than the ledger endpoint refuses: {findings:?}"
    );
}
