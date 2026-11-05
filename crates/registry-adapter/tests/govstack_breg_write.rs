// SPDX-License-Identifier: Apache-2.0

//! Maintained BReg source-pack contract and real-process GovStack Write proof.

use std::path::{Path, PathBuf};
use std::process::Command;

use registry_adapter_core::{
    check_pack, check_write_project, AdapterPack, AdapterProject, SourceWriteSupport,
    ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND, ADAPTER_PROJECT_API_VERSION, ADAPTER_PROJECT_KIND,
};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};

const PACK_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PACK_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PACK_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

const PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROJECT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

fn repository_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn read<T: serde::de::DeserializeOwned>(path: &Path, format: &'static FormatSpec<'static>) -> T {
    let bytes = std::fs::read(path).expect("read maintained authoring");
    Reader::new(path.display().to_string())
        .read(&bytes, &Expect::one(format))
        .expect("read maintained authoring through the shared reader")
        .decode::<T>()
        .expect("decode maintained authoring")
}

#[test]
fn maintained_breg_pack_and_project_declare_the_exact_single_record_guarantees() {
    let pack_path = repository_path("products/adapter/packs/breg-records/pack.yaml");
    let project_path = repository_path("products/adapter/examples/breg-govstack/project.yaml");
    let pack: AdapterPack = read(&pack_path, &PACK_FORMAT);
    let project: AdapterProject = read(&project_path, &PROJECT_FORMAT);

    let pack_findings = check_pack(&pack);
    assert!(
        pack_findings.is_empty(),
        "pack diagnostics: {pack_findings:#?}"
    );
    let write_findings = check_write_project(&project, &pack);
    assert!(
        write_findings.is_empty(),
        "write diagnostics: {write_findings:#?}"
    );

    let create = pack
        .route_templates
        .get("create-record")
        .and_then(|template| template.write_support.as_ref());
    let update = pack
        .route_templates
        .get("update-record")
        .and_then(|template| template.write_support.as_ref());
    assert!(matches!(create, Some(SourceWriteSupport::CreateOne { .. })));
    assert!(matches!(
        update,
        Some(SourceWriteSupport::ConditionalUpdateOne { .. })
    ));

    let mut scripts = registry_adapter_engine::scripts::ScriptSet::default();
    scripts
        .add(
            &pack,
            pack_path.parent().expect("pack directory"),
            "scripts/batch-request.rhai",
            "update_batch",
        )
        .expect("compile update batch mapper");
    let maps = std::sync::Arc::new(std::collections::BTreeMap::new());
    let mapped = scripts
        .call(
            &maps,
            "scripts/batch-request.rhai",
            "update_batch",
            &serde_json::json!({
                "body": {"a/b~c": "safe", "name": "Augusta Ada King", "note": null},
                "headers": {"recordid": "00000000-0000-4000-8000-000000000001"},
                "properties": {"AdapterSourceCondition": "\"breg-test\""}
            }),
        )
        .expect("map one conditional update");
    assert_eq!(
        mapped,
        serde_json::json!({"items": [{
            "operation": "patch",
            "recordIdentifier": "00000000-0000-4000-8000-000000000001",
            "ifMatch": "\"breg-test\"",
            "patch": [
                {"op": "add", "path": "/data/a~1b~0c", "value": "safe"},
                {"op": "add", "path": "/data/name", "value": "Augusta Ada King"},
                {"op": "remove", "path": "/data/note"}
            ]
        }]})
    );
}

#[test]
fn fixed_write_stays_out_of_the_read_only_external_effective_contract() {
    let scratch = tempfile::tempdir().expect("effective-contract scratch directory");
    let runtime = scratch.path().join("runtime.yaml");
    std::fs::write(
        &runtime,
        r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: breg-govstack-contract-test
endpoints:
  - endpoint: registry
    baseUrl: http://127.0.0.1:9
    credential:
      type: static-authorization
      tokenRef: secret:env/CONTRACT_TEST_SOURCE_TOKEN
listener:
  bind: 127.0.0.1:0
database:
  runtimeUrlRef: secret:env/CONTRACT_TEST_DB_URL
  migrationUrlRef: secret:env/CONTRACT_TEST_DB_URL
  testOnlyPlaintext: true
oidc:
  issuer: http://127.0.0.1:9
  audience: breg-govstack-contract-test
  allowInsecureHttp: true
  jwksSource:
    type: static
    documentRef: secret:env/CONTRACT_TEST_JWKS
allowedClients: [synthetic-client]
allowedPrivateCidrs: [192.168.0.0/16]
audit:
  retentionDays: 90
idempotency:
  responseRetentionSeconds: 86400
cursorKeyRef: secret:env/CONTRACT_TEST_CURSOR_KEY
"#,
    )
    .expect("write effective-contract runtime");
    let output = Command::new(env!("CARGO_BIN_EXE_adapter"))
        .args(["effective-contract", "--runtime-config"])
        .arg(runtime)
        .arg("--project")
        .arg(repository_path("products/adapter/examples/breg-govstack"))
        .arg("--pack")
        .arg(repository_path(
            "products/adapter/packs/breg-records/pack.yaml",
        ))
        .env("CONTRACT_TEST_SOURCE_TOKEN", "synthetic-source-token")
        .env(
            "CONTRACT_TEST_DB_URL",
            "postgresql://synthetic@localhost/synthetic",
        )
        .env("CONTRACT_TEST_JWKS", r#"{"keys":[]}"#)
        .env(
            "CONTRACT_TEST_CURSOR_KEY",
            "breg-write-cursor-key-0123456789",
        )
        .output()
        .expect("run Adapter effective-contract");
    assert!(
        output.status.success(),
        "effective-contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let contract: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("effective contract is JSON");
    let operations = contract["contract"]["operations"]
        .as_array()
        .expect("effective operations");
    let retrieve = operations
        .iter()
        .find(|operation| operation["id"] == "retrieve.contacts")
        .expect("effective contract serves retrieve.contacts");
    assert_eq!(retrieve["effect"], "read");
    assert!(retrieve.get("idempotencyReplayWindowSeconds").is_none());
    let unserved = contract["contract"]["unserved"]
        .as_array()
        .expect("unserved operations");
    for id in ["create.contacts", "update.contacts"] {
        let operation = unserved
            .iter()
            .find(|operation| operation["operationId"] == id)
            .unwrap_or_else(|| panic!("effective contract reports {id}: {contract}"));
        assert_eq!(operation["effect"], "write", "{operation}");
        assert_eq!(
            operation["reasonCode"], "adapter.operation.gateway-write-disabled",
            "{operation}"
        );
    }
}

#[cfg(feature = "postgres-test")]
#[path = "support/govstack_breg/mod.rs"]
mod native;

#[cfg(feature = "postgres-test")]
fn assert_derived_source_key(request: &native::SourceRequest, caller_key: &str) {
    let source_key = request
        .idempotency_key
        .as_deref()
        .expect("source request carries the engine-owned idempotency key");
    assert_ne!(source_key, caller_key, "the caller key never reaches BReg");
    assert_eq!(
        source_key.len(),
        64,
        "derived source key is one SHA-256 hex"
    );
    assert!(
        source_key.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "derived source key is hexadecimal"
    );
}

#[cfg(feature = "postgres-test")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_breg_and_adapter_preserve_write_receipts_conditions_and_exact_recovery() {
    use native::{batch_requests, json_body, AdapterProcess, BregDev, DropProxy};
    use serde_json::json;

    let breg = BregDev::start();
    let proxy = DropProxy::start(&breg.origin);
    let project = repository_path("products/adapter/examples/breg-govstack");
    let pack = repository_path("products/adapter/packs/breg-records/pack.yaml");
    let adapter = AdapterProcess::start(&proxy.origin(), &breg.source_token, &project, &pack).await;
    let editor = adapter.token("records.read records.write");
    let reader = adapter.token("records.read");
    let collection = "/govstack/registries/v1/collections/contacts/records";
    let replay_window_header = "x-registry-idempotency-replay-window-seconds";
    let capabilities = adapter.request(
        "GET",
        "/govstack/registries/v1/capabilities",
        &editor,
        &[],
        &[],
    );
    assert_eq!(capabilities.status, 200, "{capabilities:?}");
    assert_eq!(capabilities.header(replay_window_header), "86400");
    let capabilities = capabilities.json();
    let contact_operations = capabilities["collections"]
        .as_array()
        .and_then(|collections| {
            collections
                .iter()
                .find(|collection| collection["collectionId"] == "contacts")
        })
        .and_then(|collection| collection["operations"].as_array())
        .expect("capabilities publish the contacts collection");
    for (family, capability) in [
        ("consultation", "retrieve"),
        ("write", "create"),
        ("write", "update"),
    ] {
        assert!(
            contact_operations.iter().any(|operation| {
                operation["family"] == family && operation["capability"] == capability
            }),
            "capabilities publish {family}/{capability}: {capabilities}"
        );
    }
    let reader_capabilities = adapter.request(
        "GET",
        "/govstack/registries/v1/capabilities",
        &reader,
        &[],
        &[],
    );
    assert_eq!(reader_capabilities.status, 200, "{reader_capabilities:?}");
    let reader_capabilities = reader_capabilities.json();
    let reader_operations = reader_capabilities["collections"]
        .as_array()
        .and_then(|collections| {
            collections
                .iter()
                .find(|collection| collection["collectionId"] == "contacts")
        })
        .and_then(|collection| collection["operations"].as_array())
        .expect("reader capabilities publish the contacts collection");
    assert!(reader_operations.iter().any(|operation| {
        operation["family"] == "consultation" && operation["capability"] == "retrieve"
    }));
    assert!(
        reader_operations
            .iter()
            .all(|operation| operation["family"] != "write"),
        "the read-only caller discovers no write capability: {reader_capabilities}"
    );
    let create_body = json_body(json!({"data": {
        "name": "Ada Lovelace",
        "email": "ada@example.test",
        "note": "first note"
    }}));
    let create_headers = [
        ("Content-Type", "application/json"),
        ("Idempotency-Key", r#""create-contact-1""#),
    ];

    let before_create_requests = proxy.requests();
    let before_create = batch_requests(&before_create_requests).len();
    let created = adapter.request("POST", collection, &editor, &create_headers, &create_body);
    assert_eq!(created.status, 201, "{created:?}\n{}", adapter.stderr());
    let receipt = created.json();
    let record_id = receipt["recordId"]
        .as_str()
        .expect("create receipt recordId")
        .to_owned();
    assert_eq!(receipt["collectionId"], "contacts");
    assert_eq!(created.header(replay_window_header), "86400");
    let created_etag = created.header("etag").to_owned();
    assert_eq!(receipt["etag"], created_etag);
    assert_eq!(
        created.header("location"),
        format!("{collection}/{record_id}")
    );
    let after_create_requests = proxy.requests();
    let created_batches = batch_requests(&after_create_requests);
    assert_eq!(created_batches.len(), before_create + 1);
    assert_derived_source_key(created_batches[before_create], create_headers[1].1);

    let replay = adapter.request("POST", collection, &editor, &create_headers, &create_body);
    assert_eq!(replay.status, 201, "{replay:?}");
    assert_eq!(replay.body, created.body);
    assert_eq!(replay.header("etag"), created_etag);
    assert_eq!(replay.header("location"), created.header("location"));
    let after_replay_requests = proxy.requests();
    assert_eq!(
        batch_requests(&after_replay_requests).len(),
        before_create + 1,
        "facade replay makes no second source request"
    );

    let mismatch = adapter.request(
        "POST",
        collection,
        &editor,
        &create_headers,
        &json_body(json!({"data": {
            "name": "Changed",
            "email": "ada@example.test"
        }})),
    );
    assert_eq!(mismatch.status, 422, "{mismatch:?}");
    let after_mismatch_requests = proxy.requests();
    assert_eq!(
        batch_requests(&after_mismatch_requests).len(),
        before_create + 1,
        "idempotency mismatch makes no source request"
    );

    let denied = adapter.request(
        "POST",
        collection,
        &reader,
        &[
            ("Content-Type", "application/json"),
            ("Idempotency-Key", r#""denied-contact""#),
        ],
        &create_body,
    );
    assert_eq!(denied.status, 403, "{denied:?}");
    let after_denial_requests = proxy.requests();
    assert_eq!(
        batch_requests(&after_denial_requests).len(),
        before_create + 1,
        "facade denial makes no source request"
    );

    let record_path = format!("{collection}/{record_id}");
    let read = adapter.request("GET", &record_path, &reader, &[], &[]);
    assert_eq!(read.status, 200, "{read:?}");
    assert_eq!(read.header("etag"), created_etag);
    assert_eq!(
        read.json(),
        json!({"recordId": record_id, "data": {
            "name": "Ada Lovelace",
            "email": "ada@example.test",
            "note": "first note"
        }})
    );

    let patch_body = json_body(json!({"data": {
        "name": "Augusta Ada King",
        "note": null
    }}));
    let patched = adapter.request(
        "PATCH",
        &record_path,
        &editor,
        &[
            ("Content-Type", "application/merge-patch+json"),
            ("Idempotency-Key", r#""patch-contact-1""#),
            ("If-Match", &created_etag),
        ],
        &patch_body,
    );
    let patch_source_requests = proxy.requests();
    let patch_source_batches = batch_requests(&patch_source_requests);
    let patch_source = patch_source_batches
        .last()
        .expect("PATCH reached the BReg batch route");
    assert_eq!(
        patched.status,
        204,
        "{patched:?}\nsource request: {patch_source:?}\n{}",
        adapter.stderr()
    );
    assert_eq!(patched.header(replay_window_header), "86400");
    assert!(patched.body.is_empty(), "PATCH has no response body");
    let patched_etag = patched.header("etag").to_owned();
    assert_ne!(patched_etag, created_etag);

    let after_patch = adapter.request("GET", &record_path, &editor, &[], &[]);
    assert_eq!(after_patch.status, 200, "{after_patch:?}");
    assert_eq!(after_patch.header("etag"), patched_etag);
    let public_after_patch = json!({"recordId": record_id, "data": {
        "name": "Augusta Ada King",
        "email": "ada@example.test"
    }});
    assert_eq!(after_patch.json(), public_after_patch);

    let repeated_remove = adapter.request(
        "PATCH",
        &record_path,
        &editor,
        &[
            ("Content-Type", "application/merge-patch+json"),
            ("Idempotency-Key", r#""patch-contact-remove-again""#),
            ("If-Match", &patched_etag),
        ],
        &json_body(json!({"data": {"note": null}})),
    );
    assert_eq!(
        repeated_remove.status, 204,
        "a repeated null remove remains valid: {repeated_remove:?}"
    );
    let current_etag = repeated_remove.header("etag").to_owned();
    let after_repeated_remove = adapter.request("GET", &record_path, &editor, &[], &[]);
    assert_eq!(
        after_repeated_remove.status, 200,
        "{after_repeated_remove:?}"
    );
    assert_eq!(after_repeated_remove.header("etag"), current_etag);
    assert_eq!(after_repeated_remove.json(), public_after_patch);

    let stale_requests = proxy.requests();
    let stale_count = batch_requests(&stale_requests).len();
    let stale = adapter.request(
        "PATCH",
        &record_path,
        &editor,
        &[
            ("Content-Type", "application/merge-patch+json"),
            ("Idempotency-Key", r#""patch-contact-stale""#),
            ("If-Match", &created_etag),
        ],
        &json_body(json!({"data": {"name": "Must Not Commit"}})),
    );
    assert_eq!(stale.status, 412, "{stale:?}\n{}", adapter.stderr());
    let after_stale_requests = proxy.requests();
    assert_eq!(batch_requests(&after_stale_requests).len(), stale_count + 1);
    let after_stale = adapter.request("GET", &record_path, &editor, &[], &[]);
    assert_eq!(after_stale.header("etag"), current_etag);
    assert_eq!(after_stale.json(), public_after_patch);

    let uncertain_body = json_body(json!({"data": {
        "name": "Grace Hopper",
        "email": "grace@example.test"
    }}));
    let uncertain_headers = [
        ("Content-Type", "application/json"),
        ("Idempotency-Key", r#""create-contact-uncertain""#),
    ];
    let before_uncertain_requests = proxy.requests();
    let before_uncertain = batch_requests(&before_uncertain_requests).len();
    proxy.arm_response_drop();
    let lost = adapter.request(
        "POST",
        collection,
        &editor,
        &uncertain_headers,
        &uncertain_body,
    );
    assert_eq!(
        lost.status, 409,
        "the committed source response is held for a safe retry: {lost:?}"
    );
    assert_eq!(lost.header("retry-after"), "5");
    let recovered = adapter.request(
        "POST",
        collection,
        &editor,
        &uncertain_headers,
        &uncertain_body,
    );
    assert_eq!(recovered.status, 201, "{recovered:?}\n{}", adapter.stderr());
    let recovered_receipt = recovered.json();
    let recovered_id = recovered_receipt["recordId"]
        .as_str()
        .expect("recovered receipt recordId");
    let requests = proxy.requests();
    let batches = batch_requests(&requests);
    let uncertain = &batches[before_uncertain..];
    assert_eq!(uncertain.len(), 2, "one native exact-replay retry");
    assert_derived_source_key(uncertain[0], uncertain_headers[1].1);
    assert_eq!(uncertain[0].idempotency_key, uncertain[1].idempotency_key);
    assert_eq!(uncertain[0].body, uncertain[1].body);
    assert!(uncertain[0].response_body.is_some());
    assert_eq!(
        uncertain[0].response_body, uncertain[1].response_body,
        "BReg replays the exact native one-item receipt"
    );
    let recovered_read = adapter.request(
        "GET",
        &format!("{collection}/{recovered_id}"),
        &editor,
        &[],
        &[],
    );
    assert_eq!(recovered_read.status, 200, "{recovered_read:?}");
    assert_eq!(recovered_read.header("etag"), recovered.header("etag"));
    assert_eq!(
        recovered_read.json(),
        json!({"recordId": recovered_id, "data": {
            "name": "Grace Hopper",
            "email": "grace@example.test"
        }})
    );
}

#[cfg(feature = "postgres-test")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_reused_after_the_replay_window_is_a_new_write_at_the_source() {
    use native::{batch_requests, json_body, AdapterProcess, BregDev, DropProxy};
    use serde_json::json;

    let breg = BregDev::start();
    let proxy = DropProxy::start(&breg.origin);
    let project = repository_path("products/adapter/examples/breg-govstack");
    let pack = repository_path("products/adapter/packs/breg-records/pack.yaml");
    let retention_seconds = 2;
    let adapter = AdapterProcess::start_with_retention(
        &proxy.origin(),
        &breg.source_token,
        &project,
        &pack,
        retention_seconds,
    )
    .await;
    let editor = adapter.token("records.read records.write");
    let collection = "/govstack/registries/v1/collections/contacts/records";
    let headers = [
        ("Content-Type", "application/json"),
        ("Idempotency-Key", r#""reused-contact-key""#),
    ];
    let first_body = json_body(json!({"data": {
        "name": "Ada Lovelace",
        "email": "ada@example.test"
    }}));
    let second_body = json_body(json!({"data": {
        "name": "Grace Hopper",
        "email": "grace@example.test"
    }}));

    let first = adapter.request("POST", collection, &editor, &headers, &first_body);
    assert_eq!(first.status, 201, "{first:?}\n{}", adapter.stderr());
    let inside = adapter.request("POST", collection, &editor, &headers, &second_body);
    assert_eq!(
        inside.status, 422,
        "inside the window another body under the key is a fingerprint mismatch: {inside:?}"
    );

    std::thread::sleep(std::time::Duration::from_secs(retention_seconds + 1));
    let reused = adapter.request("POST", collection, &editor, &headers, &second_body);
    assert_eq!(
        reused.status,
        201,
        "a key past the window is processed as new: {reused:?}\n{}",
        adapter.stderr()
    );
    let first_id = first.json()["recordId"]
        .as_str()
        .expect("first receipt recordId")
        .to_owned();
    let reused_id = reused.json()["recordId"]
        .as_str()
        .expect("reused receipt recordId")
        .to_owned();
    assert_ne!(first_id, reused_id, "the source made a second record");

    let requests = proxy.requests();
    let batches = batch_requests(&requests);
    assert_eq!(batches.len(), 2, "one source write per processed request");
    assert_derived_source_key(batches[0], headers[1].1);
    assert_derived_source_key(batches[1], headers[1].1);
    assert_ne!(
        batches[0].idempotency_key, batches[1].idempotency_key,
        "a reused caller key reaches the source under a fresh native key"
    );
    let read = adapter.request(
        "GET",
        &format!("{collection}/{reused_id}"),
        &editor,
        &[],
        &[],
    );
    assert_eq!(read.status, 200, "{read:?}");
    assert_eq!(read.json()["data"]["name"], "Grace Hopper");
}
