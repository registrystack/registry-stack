// SPDX-License-Identifier: Apache-2.0
//! An independently built Scheduling service reached through its public HTTP
//! client, with its own disposable PostgreSQL schema and signed hook target.

use super::failed_fixture;

use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_scheduling_client::{
    BearerToken, SchedulingAuth, SchedulingClient, SchedulingClientConfig,
};
use serde_json::json;

pub const AUDIENCE: &str = "urn:registry-scheduling:coordinator-lifecycle";
pub const CLIENT: &str = "lifecycle-agent";
pub const HOOK_KEY: &[u8] = &[0x6b; 32];
pub const SCHEDULING_ID: &str = "coordinator-lifecycle";

fn binary(variable: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
        panic!("{variable} must point to the independently built executable; run products/coordinator/scripts/test-postgres.sh")
    }));
    assert!(
        path.is_file(),
        "{variable} must name an existing executable"
    );
    path
}

fn operator(binary: &Path, arguments: &[&std::ffi::OsStr], log: &Path) {
    let output = Command::new(binary).args(arguments).output().unwrap();
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    super::private_file(log, &bytes);
    assert!(
        output.status.success(),
        "independent Scheduling operator failed; inspect {}",
        log.display()
    );
}

pub struct Scheduling {
    _root: failed_fixture::FixtureDirectory,
    pub base_url: String,
    pub client: SchedulingClient,
    pub admin: Arc<tokio_postgres::Client>,
    signing_key: PrivateJwk,
    schema: String,
    child: Option<Child>,
}

impl Scheduling {
    pub async fn start(relay_origin: &str) -> Self {
        Self::start_with_reminders(relay_origin, None, None, None).await
    }

    pub async fn start_with_signed_reminders(
        relay_origin: &str,
        reminder_path: &str,
        confirmation_path: Option<&str>,
        reminder_offset_minutes: Option<u32>,
    ) -> Self {
        Self::start_with_reminders(
            relay_origin,
            Some(reminder_path),
            confirmation_path,
            reminder_offset_minutes,
        )
        .await
    }

    async fn start_with_reminders(
        relay_origin: &str,
        reminder_path: Option<&str>,
        confirmation_path: Option<&str>,
        reminder_offset_minutes: Option<u32>,
    ) -> Self {
        let ctl = binary("COORDINATOR_SCHEDULINGCTL_BIN");
        let runtime_binary = binary("COORDINATOR_SCHEDULING_BIN");
        let base = std::env::var("COORDINATOR_SCHEDULING_TEST_DATABASE_URL").expect(
            "COORDINATOR_SCHEDULING_TEST_DATABASE_URL must name a separate disposable database",
        );
        let schema = format!("coordinator_scheduling_{}", uuid::Uuid::new_v4().simple());
        let mut database = url::Url::parse(&base).expect("disposable database URL");
        database
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let (admin, connection) = tokio_postgres::connect(database.as_str(), tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let root = failed_fixture::FixtureDirectory::new(
            tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap(),
        );
        let project = root.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("scheduling.yaml"),
            policy(reminder_offset_minutes),
        )
        .unwrap();
        std::fs::write(project.join("records.yaml"), records()).unwrap();
        operator(
            &ctl,
            &["check".as_ref(), project.as_os_str()],
            &root.path().join("check.log"),
        );
        let package = root.path().join("package");
        operator(
            &ctl,
            &[
                "package".as_ref(),
                project.as_os_str(),
                "--output".as_ref(),
                package.as_os_str(),
            ],
            &root.path().join("package.log"),
        );
        super::private_file(&root.path().join("database"), database.as_str().as_bytes());
        super::private_file(
            &root.path().join("audit-key"),
            b"synthetic-scheduling-audit-key-32",
        );
        super::private_file(&root.path().join("hook-key"), HOOK_KEY);
        let signing_key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap();
        super::private_file(
            &root.path().join("jwks"),
            json!({"keys":[signing_key.public()]})
                .to_string()
                .as_bytes(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let path = root.path().join("scheduling-runtime.yaml");
        let mut destinations = json!({"hooks":{
            "confirmed":{"url":format!("{relay_origin}/v1/events/scheduling-lifecycle/confirmed"),"hmacSha256KeyRef":"secret:file/hook-key","maximumAttempts":1},
            "rescheduled":{"url":format!("{relay_origin}/v1/events/scheduling-lifecycle/rescheduled"),"hmacSha256KeyRef":"secret:file/hook-key","maximumAttempts":1},
            "cancelled":{"url":format!("{relay_origin}/v1/events/scheduling-lifecycle/cancelled"),"hmacSha256KeyRef":"secret:file/hook-key","maximumAttempts":1}
        }});
        if let Some(reminder_path) = reminder_path {
            let mut reminder_destination = json!({
                "url":format!("{relay_origin}{reminder_path}"),
                "hmacSha256KeyRef":"secret:file/hook-key"
            });
            if let Some(confirmation_path) = confirmation_path {
                reminder_destination["purposeUrls"] = json!({
                    "confirmation":format!("{relay_origin}{confirmation_path}"),
                    "reminder":format!("{relay_origin}{reminder_path}")
                });
            }
            destinations["reminders"] = reminder_destination;
        }
        std::fs::write(
            &path,
            serde_norway::to_string(&json!({
                "apiVersion":"id.registrystack.org/formats/scheduling/runtime/v1alpha1",
                "kind":"SchedulingRuntimeConfig",
                "identity":{"databaseId":format!("coordinator-scheduling-{}", uuid::Uuid::new_v4().simple())},
                "package":{"root":package},
                "listener":{"bind":address.to_string(),"tlsTermination":"development-loopback"},
                "secretProviders":{"file":{"root":root.path()}},
                "database":{"runtimeUrlRef":"secret:file/database","migrationUrlRef":"secret:file/database","testOnlyPlaintext":true},
                "authentication":{"oidc":{"issuer":"https://scheduling-issuer.example.invalid","audience":AUDIENCE,
                    "scopeClaim":"scope","readsScope":"scheduling:read","allowedClients":[CLIENT],
                    "jwksSource":{"type":"static","documentRef":"secret:file/jwks"}}},
                "taskGrantStatus":"unchecked-final-fifteen-minutes",
                "audit":{"destination":"file","path":root.path().join("audit/scheduling.ndjson"),"hashKeyRef":"secret:file/audit-key"},
                "destinations":destinations,
                "retention":{"receiptRetentionDays":7,"claimOwnerRetentionDays":7,"hookPayloadRetentionDays":7}
            }))
            .unwrap(),
        )
        .unwrap();
        operator(
            &ctl,
            &[
                "apply".as_ref(),
                "--runtime-config".as_ref(),
                path.as_os_str(),
            ],
            &root.path().join("apply.log"),
        );
        operator(
            &ctl,
            &[
                "records".as_ref(),
                "apply".as_ref(),
                "--runtime-config".as_ref(),
                path.as_os_str(),
                project.join("records.yaml").as_os_str(),
            ],
            &root.path().join("records.log"),
        );
        let log_path = root.path().join("service.log");
        super::private_file(&log_path, b"");
        let log = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        let child = Command::new(runtime_binary)
            .arg("--runtime-config")
            .arg(&path)
            .arg("serve")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let base_url = format!("http://{address}");
        let client = SchedulingClient::new(SchedulingClientConfig::new(
            base_url.parse().expect("Scheduling URL"),
        ))
        .unwrap();
        let mut service = Self {
            _root: root,
            base_url,
            client,
            admin: Arc::new(admin),
            signing_key,
            schema,
            child: Some(child),
        };
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let stop = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                service
                    .child
                    .as_mut()
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_none(),
                "independent Scheduling service exited; inspect {}",
                log_path.display()
            );
            if http
                .get(format!("{}/readyz", service.base_url))
                .timeout(Duration::from_secs(3))
                .send()
                .await
                .is_ok_and(|response| response.status() == reqwest::StatusCode::OK)
            {
                break;
            }
            assert!(
                Instant::now() < stop,
                "independent Scheduling service did not become ready; inspect {}",
                log_path.display()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        service
    }

    pub fn agent_token(&self) -> BearerToken {
        token(&self.signing_key, true)
    }

    pub fn reader_token(&self) -> BearerToken {
        token(&self.signing_key, false)
    }

    pub fn auth<'a>(&self, token: &'a BearerToken) -> SchedulingAuth<'a> {
        SchedulingAuth::new(token)
    }

    pub async fn stop(mut self) {
        self.stop_child();
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }

    fn stop_child(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for Scheduling {
    fn drop(&mut self) {
        self.stop_child();
    }
}

fn token(key: &PrivateJwk, with_grant: bool) -> BearerToken {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss":"https://scheduling-issuer.example.invalid",
        "aud":AUDIENCE,
        "sub":"coordinator-lifecycle-agent",
        "azp":CLIENT,
        "scope":"scheduling:read",
        "registry_actor_kind":if with_grant { "agent" } else { "service" },
        "iat":now,
        "exp":now + 300
    });
    if with_grant {
        claims.as_object_mut().unwrap().extend(
            json!({
                "registry_purpose":"synthetic-lifecycle-notice",
                "registry_grant_id":uuid::Uuid::new_v4(),
                "registry_grant_source_issuer":"https://task-authority.example.invalid",
                "registry_grant_client":CLIENT,
                "registry_grant_resource":AUDIENCE,
                "registry_grant_exp":now + 600,
                "registry_grant_bounds":{"type":"scheduling","permissions":[{
                    "service":"registry-update","location":"north-counter",
                    "actions":["appointment.create","appointment.reschedule","appointment.cancel"]
                }]},
                "identity":{"subject_reference":"synthetic-subject"},
                "registry_approver":"synthetic-approver"
            })
            .as_object()
            .unwrap()
            .clone(),
        );
    }
    let header = json!({"alg":"ES256","kid":key.kid,"typ":"at+jwt"});
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header}.{claims}");
    let signature = URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes(), key).unwrap());
    BearerToken::new(format!("{signing_input}.{signature}")).unwrap()
}

fn policy(reminder_offset_minutes: Option<u32>) -> String {
    let today = Utc::now().date_naive();
    let effective_from = today - chrono::Days::new(1);
    let effective_until = today + chrono::Days::new(90);
    r#"apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1
kind: SchedulingProject
project: {id: coordinator-lifecycle, version: "1"}
services: [{id: registry-update, label: Registry record update}]
channels: [public]
holidaySets: [{id: none, revision: 1, because: Synthetic test calendar.}]
openings:
  - id: all-day
    location: north-counter
    holidaySet: none
    weekdays: [mon, tue, wed, thu, fri, sat, sun]
    startTime: "00:00"
    endTime: "23:30"
    effectiveFrom: "$EFFECTIVE_FROM"
    effectiveUntil: "$EFFECTIVE_UNTIL"
    because: Synthetic all-day opening for the native composition test.
offerings:
  - id: registry-update-30
    service: registry-update
    label: Registry record update appointment
    mode: exact-time
    location: north-counter
    because: Synthetic appointment for the native composition test.
    cancellationCutoffMinutes: 60
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 0
      bufferAfterMinutes: 0
      leadTimeMinutes: 60
      horizonDays: 60
      pool: north-counter
      startIncrementMinutes: 30
      maximumRecipients: 1
    duplicateActiveKey: subject
$REMINDERS
holdPolicy: {ttlMinutes: 5, maximumPerCaller: 2, because: Synthetic hold policy.}
hooks:
  - id: appointment-confirmed
    phase: after
    trigger: appointment.confirmed
    projection: [appointmentId, offering, start, end, policyRevision, revision, state]
    handler: {type: url, destinationId: confirmed}
  - id: appointment-rescheduled
    phase: after
    trigger: appointment.rescheduled
    projection: [appointmentId, offering, start, end, policyRevision, revision, state]
    handler: {type: url, destinationId: rescheduled}
  - id: appointment-cancelled
    phase: after
    trigger: appointment.cancelled
    projection: [appointmentId, revision, state]
    handler: {type: url, destinationId: cancelled}
"#
    .replace("$EFFECTIVE_FROM", &effective_from.to_string())
    .replace("$EFFECTIVE_UNTIL", &effective_until.to_string())
    .replace(
        "$REMINDERS",
        &reminder_offset_minutes.map_or_else(String::new, |offset| {
            format!(
                "    reminders:\n      - offsetMinutes: {offset}\n        because: Synthetic authored reminder for the native composition test."
            )
        }),
    )
}

fn records() -> &'static str {
    r#"apiVersion: id.registrystack.org/formats/scheduling/records/v1alpha1
kind: SchedulingRecords
locations: [{id: north-counter, timezone: UTC}]
pools:
  - id: north-counter
    members: [{resourceId: station-1, available: true}]
exceptions: []
"#
}
