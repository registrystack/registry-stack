// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use registry_platform_canonical_json::canonicalize_json;
use serde_json::Value;

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);
const EVENT_ID: &str = "record-created-v1";
const EVENT_VALUE_CANARY: &str = "webhook-event-value-canary";
const PATH_VALUE_CANARY: &str = "webhook-runtime-path-value-canary";

struct TestProject {
    root: PathBuf,
}

impl TestProject {
    fn create() -> Self {
        let root = std::env::current_dir()
            .expect("current directory is available")
            .join(format!(
                "registry-serverctl-webhook-test-{}-{}",
                std::process::id(),
                TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&root).expect("test project directory creates");
        fs::write(
            root.join("registry.yaml"),
            br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: webhook-sample
  version: 1
  defaultLanguage: en
entities:
  - id: record
    route: records
    mutationMode: mutable
    fields:
      - id: active
        type: boolean
        classification: internal
      - id: count
        type: int64
        classification: internal
      - id: observed-at
        type: timestamp
        classification: internal
      - id: status
        type: vocabulary-code
        vocabulary: record-status
        values: [ready, closed]
        classification: internal
    events:
      - id: record-created-v1
        trigger: created
        projection: [active, count, observed-at, status]
        webhook:
          destinationId: sample-receiver
"#,
        )
        .expect("test project writes");
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for TestProject {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("test project directory removes");
        }
    }
}

fn run<I, T>(arguments: I) -> (u8, String, String)
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_serverctl::run_from(arguments, &mut stdout, &mut stderr);
    (
        if status == std::process::ExitCode::SUCCESS {
            0
        } else {
            1
        },
        String::from_utf8(stdout).expect("stdout is UTF-8"),
        String::from_utf8(stderr).expect("stderr is UTF-8"),
    )
}

#[test]
fn sample_is_an_exact_deterministic_cloudevents_request_without_deployment_authority() {
    let project = TestProject::create();
    let (status, first, stderr) = run([
        OsStr::new("registry-serverctl"),
        OsStr::new("--format"),
        OsStr::new("json"),
        OsStr::new("webhook"),
        OsStr::new("sample"),
        project.path().as_os_str(),
        OsStr::new("--event"),
        OsStr::new(EVENT_ID),
    ]);
    let (second_status, second, second_stderr) = run([
        OsStr::new("registry-serverctl"),
        OsStr::new("--format"),
        OsStr::new("json"),
        OsStr::new("webhook"),
        OsStr::new("sample"),
        project.path().as_os_str(),
        OsStr::new("--event"),
        OsStr::new(EVENT_ID),
    ]);

    assert_eq!((status, second_status), (0, 0));
    assert!(stderr.is_empty());
    assert!(second_stderr.is_empty());
    assert_eq!(first, second);
    let report: Value = serde_json::from_str(&first).expect("sample report is JSON");
    assert_eq!(report["ok"], true);
    assert_eq!(report["command"], "webhook sample");
    assert_eq!(report["eventId"], EVENT_ID);
    assert_eq!(report["request"]["method"], "POST");
    assert_eq!(
        report["request"]["requestTarget"],
        "<configured-webhook-request-target>"
    );
    let headers = report["request"]["headers"]
        .as_object()
        .expect("headers are an object");
    assert_eq!(
        headers.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "Accept",
            "Content-Type",
            "Idempotency-Key",
            "X-Registry-Delivery-Attempt",
            "X-Registry-Delivery-Time",
            "X-Registry-Event-Generation",
            "X-Registry-Signature",
            "ce-dataschema",
            "ce-id",
            "ce-source",
            "ce-specversion",
            "ce-time",
            "ce-type",
        ])
    );
    assert_eq!(headers["ce-specversion"], "1.0");
    assert_eq!(headers["ce-type"], EVENT_ID);
    assert_eq!(
        headers["ce-source"],
        "urn:registrystack:registry:webhook-sample:instance:<configured-instance>"
    );
    assert_eq!(headers["X-Registry-Signature"], "v1=<computed-at-delivery>");
    assert!(headers["ce-dataschema"]
        .as_str()
        .expect("data schema is text")
        .starts_with(
            "urn:registry-server:event-schema:webhook-sample:record:record-created-v1:sha256:"
        ));
    assert_eq!(
        report["request"]["body"]["values"],
        serde_json::json!({
            "active": true,
            "count": 1,
            "observed-at": "2026-01-01T00:00:00Z",
            "status": "ready"
        })
    );
    let canonical =
        canonicalize_json(&report["request"]["body"]).expect("sample body canonicalizes");
    assert_eq!(
        report["request"]["canonicalBody"],
        String::from_utf8(canonical).expect("canonical body is UTF-8")
    );
    assert!(!first.contains("hmacSha256KeyRef"));
    assert!(!first.contains("https://"));
}

#[test]
fn unavailable_sample_event_is_value_free_and_field_addressed() {
    let project = TestProject::create();
    let (status, stdout, stderr) = run([
        OsStr::new("registry-serverctl"),
        OsStr::new("--format"),
        OsStr::new("json"),
        OsStr::new("webhook"),
        OsStr::new("sample"),
        project.path().as_os_str(),
        OsStr::new("--event"),
        OsStr::new(EVENT_VALUE_CANARY),
    ]);

    assert_eq!(status, 1);
    assert!(stderr.is_empty());
    assert!(!stdout.contains(EVENT_VALUE_CANARY));
    let report: Value = serde_json::from_str(&stdout).expect("failure is JSON");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "webhook.sample.event_refused"
    );
    assert_eq!(report["diagnostics"][0]["path"], "event");
    assert_eq!(report["diagnostics"][0]["artifact"], "webhook_sample");
    assert_eq!(
        report["diagnostics"][0]["suggestedAction"],
        "select_webhook_event"
    );
}

#[test]
fn operator_commands_share_one_value_free_refusal() {
    let relative = Path::new(PATH_VALUE_CANARY);
    let cases = [
        vec![
            OsStr::new("registry-serverctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("webhook"),
            OsStr::new("list"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
        ],
        vec![
            OsStr::new("registry-serverctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("webhook"),
            OsStr::new("replay"),
            OsStr::new("--runtime-config"),
            relative.as_os_str(),
            OsStr::new("--event-id"),
            OsStr::new("00000000-0000-4000-8000-000000000001"),
            OsStr::new("--delivery-id"),
            OsStr::new("record.record-created-v1.webhook"),
            OsStr::new("--expected-generation"),
            OsStr::new("1"),
        ],
    ];

    for arguments in cases {
        let (status, stdout, stderr) = run(arguments);
        assert_eq!(status, 1);
        assert!(stderr.is_empty());
        assert!(!stdout.contains(PATH_VALUE_CANARY));
        let report: Value = serde_json::from_str(&stdout).expect("failure is JSON");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "webhook.operation.refused"
        );
        assert_eq!(report["diagnostics"][0]["path"], "webhook");
        assert_eq!(report["diagnostics"][0]["artifact"], "webhook_operations");
    }
}

#[test]
fn webhook_help_describes_the_bounded_operator_contract() {
    let (status, stdout, stderr) = run(["registry-serverctl", "webhook", "list", "--help"]);

    assert_eq!(status, 0);
    assert!(stderr.is_empty());
    assert!(stdout.contains("--runtime-config <ABSOLUTE_FILE>"));
    assert!(stdout.contains("--limit <COUNT>"));
    assert!(stdout.contains("[default: 50]"));
    assert!(stdout.contains("value-free"));
}
