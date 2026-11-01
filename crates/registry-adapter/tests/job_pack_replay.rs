// SPDX-License-Identifier: Apache-2.0

//! The maintained job packs replayed against their own fixtures
//! (`products/adapter/CONCEPT.md` sections 17.1 and 17.2): the
//! kobotoolbox and odk-central packs, compiled through the job compiler
//! with their example job, profile, and project, run one page per
//! fixture entry against the loopback double. Each entry pins the
//! request the route sends (method, path, query) and the item page or
//! problem class the run produces. The fixtures are synthetic and
//! `documented`: nothing here ran against a real KoboToolbox or ODK
//! Central server.

use std::path::{Path, PathBuf};
use std::sync::Once;

use registry_adapter::engine::job::{compile_job_with, run_job_page, JobProgram};
use serde_json::{json, Value};

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

/// The credential references the example runtime documents, set to
/// stand-in values the double never checks.
fn set_credentials() {
    static CREDENTIALS: Once = Once::new();
    CREDENTIALS.call_once(|| {
        for name in [
            "KOBO_USERNAME",
            "KOBO_PASSWORD",
            "ODK_EMAIL",
            "ODK_PASSWORD",
        ] {
            std::env::set_var(name, "replay");
        }
    });
}

fn adapter_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter")
}

/// One replayed source: the pack, its example workspace, the endpoint
/// the route sends to, the credential references, and the base path the
/// runtime binds (the deployment-owned scoping of the pack header).
struct Source {
    pack: &'static str,
    example: &'static str,
    endpoint: &'static str,
    username_ref: &'static str,
    password_ref: &'static str,
    base_path: &'static str,
}

const KOBO: Source = Source {
    pack: "kobotoolbox",
    example: "kobotoolbox-job",
    endpoint: "kobo-api",
    username_ref: "secret:env/KOBO_USERNAME",
    password_ref: "secret:env/KOBO_PASSWORD",
    base_path: "/api/v2/assets/aFixtureUid0000000000000000000001/data",
};

const ODK: Source = Source {
    pack: "odk-central",
    example: "odk-central-job",
    endpoint: "odk-odata",
    username_ref: "secret:env/ODK_EMAIL",
    password_ref: "secret:env/ODK_PASSWORD",
    base_path: "/v1/projects/1/forms/fixture-form.svc/Submissions",
};

const ODK_REPEATS: Source = Source {
    base_path: "/v1/projects/1/forms/fixture-form.svc/Submissions.household.member",
    ..ODK
};

#[allow(
    clippy::disallowed_methods,
    reason = "the test reads a committed example, pack or fixture to build its input; it reads no operator configuration"
)]
fn read_yaml(path: &Path) -> Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_norway::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is YAML: {error}", path.display()))
}

/// Compile the pack's example job against a runtime that binds the
/// endpoint to the double. `route` names another source route of the
/// same pack: the example job is copied with that route, the way the
/// example job header tells a deployment to.
#[allow(
    clippy::disallowed_methods,
    reason = "the test reads a committed example job and writes its scratch copy; it reads no operator configuration"
)]
fn compile(
    source: &Source,
    double: &upstream::UpstreamDouble,
    route: Option<&str>,
) -> (JobProgram, tempfile::TempDir) {
    set_credentials();
    let example = adapter_root().join("examples").join(source.example);
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let runtime = json!({
        "apiVersion": "id.registrystack.org/formats/adapter/job-runtime/v1alpha1",
        "kind": "AdapterJobRuntimeConfig",
        "id": "job-pack-replay",
        "endpoints": [{
            "endpoint": source.endpoint,
            "baseUrl": double.url(source.base_path),
            "credential": {
                "type": "basic",
                "usernameRef": source.username_ref,
                "passwordRef": source.password_ref,
            },
        }],
        "allowedPrivateCidrs": ["10.0.0.0/8"],
    });
    let runtime_path = scratch.path().join("runtime.yaml");
    std::fs::write(
        &runtime_path,
        serde_json::to_string_pretty(&runtime).expect("the runtime renders"),
    )
    .expect("the runtime is written");
    let mut job_path = example.join("job.yaml");
    if let Some(route) = route {
        let text = std::fs::read_to_string(&job_path).expect("the example job is readable");
        let mut job: Value = serde_norway::from_str(&text).expect("the example job is YAML");
        job["source"]["route"] = json!(route);
        job_path = scratch.path().join("job.yaml");
        std::fs::write(
            &job_path,
            serde_json::to_string_pretty(&job).expect("the job renders"),
        )
        .expect("the job copy is written");
    }
    let program = compile_job_with(
        &adapter_root()
            .join("packs")
            .join(source.pack)
            .join("pack.yaml"),
        &job_path,
        &runtime_path,
        &example.join("profile.yaml"),
        &example.join("project.yaml"),
    )
    .unwrap_or_else(|error| panic!("the {} example job compiles: {error:?}", source.pack));
    (program, scratch)
}

/// Replay every entry of one fixture: each entry runs on a fresh double
/// and a fresh compile, so no entry leans on another's request record.
async fn replay(source: &Source, route: Option<&str>, fixture: &str) {
    let path = adapter_root()
        .join("packs")
        .join(source.pack)
        .join("fixtures")
        .join(fixture);
    let document = read_yaml(&path);
    let entries = document["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("{fixture} carries entries"));
    assert!(!entries.is_empty(), "{fixture} carries at least one entry");
    for (index, entry) in entries.iter().enumerate() {
        replay_entry(source, route, &format!("{fixture} entry {index}"), entry).await;
    }
}

/// Replay one entry in the fixture entry shape: the scripted exchanges
/// answer the route's sends, and the page or problem class must match.
async fn replay_entry(source: &Source, route: Option<&str>, label: &str, entry: &Value) {
    let double = upstream::UpstreamDouble::start();
    let exchanges = entry["upstream"]
        .as_array()
        .unwrap_or_else(|| panic!("{label} carries upstream exchanges"));
    double.respond_with(
        exchanges
            .iter()
            .map(|exchange| {
                let response = &exchange["response"];
                let status = response["status"]
                    .as_u64()
                    .and_then(|status| u16::try_from(status).ok())
                    .unwrap_or_else(|| panic!("{label} carries a response status"));
                upstream::Response::json(status, &response["body"].to_string())
            })
            .collect(),
    );
    let (program, _scratch) = compile(source, &double, route);
    let cursor = Some(entry["jobRun"]["cursor"].clone()).filter(|cursor| !cursor.is_null());
    let result = run_job_page(&program, cursor).await;

    let requests = double.requests();
    assert_eq!(
        requests.len(),
        exchanges.len(),
        "{label}: the route sends one request per scripted exchange"
    );
    for (request, exchange) in requests.iter().zip(exchanges) {
        let expected = &exchange["request"];
        assert_eq!(
            expected["endpoint"], source.endpoint,
            "{label}: the fixture names the endpoint"
        );
        assert_eq!(request.method, expected["method"].as_str().unwrap_or(""));
        let path = expected["path"].as_str().unwrap_or("");
        let query = expected["query"].as_str().unwrap_or("");
        let target = if query.is_empty() {
            format!("{}{path}", source.base_path)
        } else {
            format!("{}{path}?{query}", source.base_path)
        };
        assert_eq!(request.target, target, "{label}: the request target");
    }

    let expected = &entry["expected"];
    match expected["type"].as_str() {
        Some("page") => {
            let result =
                result.unwrap_or_else(|failure| panic!("{label}: the page runs: {failure:?}"));
            assert_eq!(
                result.page.to_value(),
                expected["page"],
                "{label}: the item page"
            );
        }
        Some("problem") => {
            let failure = match result {
                Ok(result) => panic!("{label}: expected a problem, got {:?}", result.page),
                Err(failure) => failure,
            };
            assert_eq!(
                failure.class.map(|class| class.class()),
                expected["class"].as_str(),
                "{label}: the problem class"
            );
        }
        other => panic!("{label}: unknown expected type {other:?}"),
    }
}

#[tokio::test]
async fn kobotoolbox_first_run_reads_a_full_page_from_the_start() {
    replay(&KOBO, None, "kobotoolbox-submissions-page-one.yaml").await;
}

#[tokio::test]
async fn kobotoolbox_continuation_reads_after_the_last_id() {
    replay(&KOBO, None, "kobotoolbox-submissions-page-two.yaml").await;
}

#[tokio::test]
async fn kobotoolbox_tail_pass_picks_up_new_submissions_and_holds_the_tail() {
    replay(&KOBO, None, "kobotoolbox-submissions-page-short.yaml").await;
}

#[tokio::test]
async fn kobotoolbox_empty_page_keeps_the_position() {
    replay(&KOBO, None, "kobotoolbox-submissions-page-empty.yaml").await;
}

#[tokio::test]
async fn kobotoolbox_refused_credential_raises_credential_rejected() {
    replay(&KOBO, None, "kobotoolbox-submissions-unauthorized.yaml").await;
}

#[tokio::test]
async fn odk_central_first_run_reads_a_full_page_in_submission_order() {
    replay(&ODK, None, "odk-central-submissions-page-one.yaml").await;
}

#[tokio::test]
async fn odk_central_continuation_filters_past_the_last_submission() {
    replay(&ODK, None, "odk-central-submissions-page-two.yaml").await;
}

#[tokio::test]
async fn odk_central_tail_pass_picks_up_new_submissions_and_holds_the_tail() {
    replay(&ODK, None, "odk-central-submissions-page-short.yaml").await;
}

#[tokio::test]
async fn odk_central_empty_page_keeps_the_position() {
    replay(&ODK, None, "odk-central-submissions-empty.yaml").await;
}

#[tokio::test]
async fn odk_central_refused_credential_raises_credential_rejected() {
    replay(&ODK, None, "odk-central-submissions-unauthorized.yaml").await;
}

#[tokio::test]
async fn odk_central_repeat_rows_key_on_their_own_id() {
    replay(
        &ODK_REPEATS,
        Some("odk-repeats"),
        "odk-central-repeats-page.yaml",
    )
    .await;
}

/// One entry whose reply the route must refuse with the `script` class,
/// in the fixture entry shape.
fn refused_entry(cursor: Value, query: &str, body: Value) -> Value {
    json!({
        "jobRun": {"cursor": cursor},
        "upstream": [{
            "request": {"endpoint": "", "method": "GET", "path": "/", "query": query},
            "response": {"status": 200, "body": body},
        }],
        "expected": {"type": "problem", "class": "script"},
    })
}

fn with_endpoint(mut entry: Value, endpoint: &str) -> Value {
    entry["upstream"][0]["request"]["endpoint"] = json!(endpoint);
    entry
}

fn kobo_submission(id: i64) -> Value {
    json!({
        "_id": id,
        "_uuid": format!("{id:08x}-0000-4000-8000-0000000f1c7e"),
        "respondent_name": format!("Fixture Respondent {id}"),
    })
}

#[tokio::test]
async fn kobotoolbox_reply_reaching_back_past_the_cursor_is_refused() {
    // A server that ignored the keyset filter answers from the first
    // submission again; handing out its last id would repeat a page.
    let entry = refused_entry(
        json!({"afterId": 130}),
        "format=json&limit=100&query=%7B%22_id%22%3A%7B%22%24gt%22%3A130%7D%7D&sort=%7B%22_id%22%3A1%7D",
        json!({"count": 2, "next": null, "previous": null,
               "results": [kobo_submission(1), kobo_submission(2)]}),
    );
    replay_entry(
        &KOBO,
        None,
        "kobo out of order",
        &with_endpoint(entry, "kobo-api"),
    )
    .await;
}

#[tokio::test]
async fn kobotoolbox_name_that_is_both_a_leaf_and_a_group_is_refused() {
    let mut submission = kobo_submission(1);
    submission["household"] = json!("a leaf");
    submission["household/household_size"] = json!(3);
    let entry = refused_entry(
        Value::Null,
        "format=json&limit=100&sort=%7B%22_id%22%3A1%7D",
        json!({"count": 1, "next": null, "previous": null, "results": [submission]}),
    );
    replay_entry(
        &KOBO,
        None,
        "kobo leaf and group",
        &with_endpoint(entry, "kobo-api"),
    )
    .await;
}

#[tokio::test]
async fn odk_central_reply_reaching_back_before_the_cursor_date_is_refused() {
    // A server that ignored `$filter` answers from an earlier date; the
    // page would hand out a position behind the one already held.
    let entry = refused_entry(
        json!({"submissionDate": "2026-08-06T02:20:00.000Z",
               "seen": ["uuid:00000000-0000-4000-8000-000000000100"]}),
        "%24filter=__system%2FsubmissionDate%20ge%202026-08-06T02%3A20%3A00.000Z&%24orderby=__system%2FsubmissionDate%20asc&%24top=100",
        json!({"value": [{
            "__id": "uuid:00000000-0000-4000-8000-000000000001",
            "__system": {"submissionDate": "2026-08-06T00:11:00.000Z", "updatedAt": null},
        }]}),
    );
    replay_entry(
        &ODK,
        None,
        "odk out of order",
        &with_endpoint(entry, "odk-odata"),
    )
    .await;
}

#[tokio::test]
async fn odk_central_repeat_route_bound_to_the_submissions_set_is_refused() {
    // A submission row carries no parent reference: the odk-repeats
    // route bound to the Submissions entity set fails instead of
    // passing submissions off as repeat rows.
    let entry = refused_entry(
        Value::Null,
        "%24orderby=%24root%2FSubmissions%2F__system%2FsubmissionDate%20asc&%24skip=0&%24top=100",
        json!({"value": [{
            "__id": "uuid:00000000-0000-4000-8000-000000000001",
            "__system": {"submissionDate": "2026-08-06T00:11:00.000Z", "updatedAt": null},
        }]}),
    );
    replay_entry(
        &ODK_REPEATS,
        Some("odk-repeats"),
        "odk repeats misbound",
        &with_endpoint(entry, "odk-odata"),
    )
    .await;
}
