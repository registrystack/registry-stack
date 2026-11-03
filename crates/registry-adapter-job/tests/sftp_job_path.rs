// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "job-sftp")]

use std::sync::Arc;
use std::time::Duration;

use registry_adapter_engine::component::sftp::{
    SftpFile, SftpRead, SftpReadFault, SftpReadResult, SftpSource,
};
use registry_adapter_engine::job::{compile_job, run_job_page};
use serde_json::json;

const BASE_PACK: &str =
    include_str!("../../../products/adapter/fixtures/corpus/base-job/pack.yaml");
const BASE_PROFILE: &str =
    include_str!("../../../products/adapter/fixtures/corpus/base-job/profile.yaml");

#[derive(Debug)]
struct StaticSftp;

impl SftpSource for StaticSftp {
    fn read<'a>(
        &'a self,
        request: SftpRead,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<SftpReadResult, SftpReadFault>> + Send + 'a>,
    > {
        Box::pin(async move {
            assert!(request.deadline > tokio::time::Instant::now());
            assert_eq!(request.maximum_file_bytes, 1_048_576);
            Ok(SftpReadResult {
                file: Some(SftpFile {
                    name: "submissions.csv".to_owned(),
                    bytes: b"id,status,note\n001,new,ready\n".to_vec(),
                }),
                more_candidates: false,
                listing_entries: 2,
            })
        })
    }
}

#[tokio::test]
async fn compiled_sftp_source_runs_through_the_shared_csv_decoder() {
    let root = tempfile::tempdir().expect("SFTP job fixture");
    let pack_text = BASE_PACK
        .replace("component: file", "component: sftp")
        .replace("uri: file:submissions", "uri: sftp:submissions");
    let pack_digest = registry_platform_config::sha256_uri(pack_text.as_bytes());
    let profile_digest = registry_platform_config::sha256_uri(BASE_PROFILE.as_bytes());
    let pack = root.path().join("pack.yaml");
    let profile = root.path().join("profile.yaml");
    let project = root.path().join("project.yaml");
    let job = root.path().join("job.yaml");
    let runtime = root.path().join("runtime.yaml");
    std::fs::write(&pack, pack_text).expect("pack");
    std::fs::write(&profile, BASE_PROFILE).expect("profile");
    std::fs::write(
        &project,
        format!(
            r#"apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1
kind: AdapterProject
project: {{ id: case-api-example, version: "1" }}
profile: {{ id: case-api, version: "1", digest: {profile_digest} }}
pack: {{ id: case-api-pack, version: "1", digest: {pack_digest} }}
recordTypes:
  - name: case
    fields:
      - {{ name: case_type, type: string, required: true }}
templatedRoutes:
  - {{ routeTemplate: find-cases, routeId: case-find }}
bindings:
  - id: case-get
    operation: cases-get
    recordType: case
    route: case-find
    maximumUpstreamCalls: 4
accessProfiles:
  - {{ id: case-reader, scopes: [cases.read], operations: [cases-get], recordTypes: [case] }}
"#
        ),
    )
    .expect("project");
    std::fs::write(
        &job,
        format!(
            r#"apiVersion: id.registrystack.org/formats/adapter/job/v1alpha1
kind: AdapterJob
job: {{ id: sftp-daily, version: "1" }}
source:
  pack: {{ id: case-api-pack, version: "1", digest: {pack_digest} }}
  route: kobo-submissions
destination:
  type: signed-coordinator-event
  binding: coordinator-test
  workflow: case-ingestion
  trigger: submitted
  source: urn:registry-adapter:job:sftp-daily
  eventType: org.example.case-submitted.v1
  dataSchema: urn:example:schema:case-submitted:v1
projection: {{ fields: [id, status, note] }}
triggers: [{{ kind: interval, delayMilliseconds: 60000 }}]
profile:
  pageDeadlineMilliseconds: 30000
  maximumResponseBytes: 16777216
  maximumPageItems: 10
  maximumPageBytes: 65536
  maximumUpstreamCalls: 2
  read:
    maximumFileBytes: 1048576
    maximumRowBytes: 4096
    maximumFieldBytes: 1024
    maximumRowsPerPage: 10
"#
        ),
    )
    .expect("job");
    std::fs::write(
        &runtime,
        serde_json::to_vec_pretty(&json!({
            "apiVersion": "id.registrystack.org/formats/adapter/job-runtime/v1alpha1",
            "kind": "AdapterJobRuntimeConfig",
            "id": "sftp-job-test",
            "endpoints": [{
                "endpoint": "cases",
                "baseUrl": "https://cases.example.invalid",
                "anonymousHttps": "operator-approved",
                "credential": {"type": "none"}
            }],
            "sources": {"sftp": {"submissions": {
                "host": "sftp.example.invalid",
                "user": "reader",
                "baseDirectory": "/incoming",
                "pinnedHostKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICoQKxIefwQBJFdRr3dchDZo9M49PcI7Vwd7X5p40mKO",
                "credential": {"type": "password", "passwordRef": "secret:env/SFTP_PASSWORD"},
                "namespace": "submissions",
                "include": "*.csv",
                "completion": {"type": "done-file", "name": "$simple{file:name}.done"},
                "maximumListingEntries": 16
            }}},
            "allowedPrivateCidrs": ["10.0.0.0/8"]
        }))
        .expect("runtime JSON"),
    )
    .expect("runtime");

    let mut program = compile_job(&pack, &job, &runtime).expect("SFTP job compiles");
    program
        .register_sftp_source("submissions", Arc::new(StaticSftp))
        .expect("source registers");
    let page = tokio::time::timeout(Duration::from_secs(2), run_job_page(&program, None))
        .await
        .expect("page deadline")
        .expect("page runs");
    assert_eq!(page.page.items.len(), 1);
    assert_eq!(
        page.page.items[0].value,
        json!({"id": "001", "status": "new", "note": "ready"})
    );
}
