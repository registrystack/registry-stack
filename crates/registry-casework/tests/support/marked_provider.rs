// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{BufRead, BufReader, Write as _};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::Duration;

use registry_casework_core::{
    ContentDigest, EphemeralCredential, HumanDisplayRequest, ReviewContextError,
    ReviewContextIdentity, ReviewContextProvider, SubjectBinding,
};
use registry_platform_config::{DeclaredPosture, Posture, PostureSource};
use serde_json::json;

const PROJECT: &str =
    include_str!("../../../../products/casework/examples/canonical-review/casework.yaml");
const SCHEMA: &str = include_str!(
    "../../../../products/casework/examples/canonical-review/schemas/correct-address.schema.json"
);
const ID: &str = "00000000-0000-4000-8000-000000000001";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
// P-256 generator point (private scalar 1). Public synthetic fixture for parsing only.
const TEST_JWK: &str = r#"{"kty":"EC","alg":"ES256","kid":"marked-peer-fixture","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}"#;

pub(crate) const POSTURES: [DeclaredPosture; 2] = [
    DeclaredPosture {
        posture: Posture::Production,
        source: PostureSource::Flag,
    },
    DeclaredPosture {
        posture: Posture::Development,
        source: PostureSource::Flag,
    },
];

pub(crate) struct Fixture {
    pub(crate) runtime: PathBuf,
    identity: ReviewContextIdentity,
    server: JoinHandle<()>,
    _root: tempfile::TempDir,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap();
        let package = path.join("package");
        let secrets = path.join("secrets");
        let schema: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
        let context = &schema["x-registry-review-context"];
        let action = &context["actionId"];
        let contract = json!({
            "id": schema["$id"],
            "revision": schema["x-registry-definition-revision"],
            "schemaDigest": registry_platform_config::sha256_uri(SCHEMA.as_bytes()),
        });
        let description = json!({
            "apiVersion": registry_casework_breg::DESCRIPTION_API_VERSION,
            "kind": registry_casework_breg::DESCRIPTION_KIND,
            "sourceNamespace": "facility-registry",
            "actionId": action,
            "contextId": context["contextId"],
            "contract": contract,
            "schema": schema,
            "schemaBytes": SCHEMA,
        });
        fs::create_dir_all(package.join("context-providers")).unwrap();
        fs::create_dir(package.join("schemas")).unwrap();
        fs::write(package.join("schemas/correct-address.schema.json"), SCHEMA).unwrap();
        fs::write(
            package.join(registry_casework::POLICY_FILE),
            PROJECT.replace(
                "    capabilities: [human-display, service-status]",
                "    description: context-providers/facility.json\n    capabilities: [human-display, service-status]",
            ),
        ).unwrap();
        fs::write(
            package.join("context-providers/facility.json"),
            description.to_string(),
        )
        .unwrap();
        registry_platform_config::write_sum_file(
            &package,
            None,
            &registry_casework::package_limits(),
            registry_casework::PACKAGE_COMMAND,
        )
        .unwrap();
        fs::create_dir(&secrets).unwrap();
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, contents) in [("client-id", "synthetic-client"), ("client-key", TEST_JWK)] {
            let file = secrets.join(name);
            fs::write(&file, contents).unwrap();
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let runtime = path.join("runtime.yaml");
        fs::write(&runtime, json!({
            "apiVersion": registry_casework::RUNTIME_CONFIG_API_VERSION,
            "kind": registry_casework::RUNTIME_CONFIG_KIND,
            "identity": {"databaseId": "peer-test"},
            "package": {"root": package},
            "listener": {"bind": "127.0.0.1:8100", "tlsTermination": "loopback-plaintext"},
            "secretProviders": {"file": {"root": secrets}},
            "database": {"runtimeUrlRef": "secret:file/db", "migrationUrlRef": "secret:file/migration"},
            "authentication": {"oidc": {"issuers": {"main": {
                "issuer": "https://identity.example.test", "audience": "urn:example:casework",
                "allowedClients": ["casework-test"],
            }}}},
            "audit": {"path": path.join("audit.ndjson"), "hashKeyRef": "secret:file/audit"},
            "contextProviders": {"facility-registry": {
                "baseUrl": url,
                "statusProfile": "casework-review-status",
                "tokenEndpoint": format!("{url}/token"),
                "clientAssertionAudience": url,
                "clientIdRef": "secret:file/client-id",
                "clientAssertionKeyRef": "secret:file/client-key",
            }},
        }).to_string()).unwrap();

        let subject = json!({"source":"facility-registry","subjectType":"proposal","id":ID,
            "version":"1","digest":DIGEST});
        let metadata = json!({"metadataVersion":"2","id":"facility-registry","version":"1",
            "revision":DIGEST,"recordTypes":[],"operations":[],"proposals":{"method":"GET",
            "path":"/v1/proposals","accessProfiles":[],"get":{"method":"GET",
            "path":"/v1/proposals/{proposal_id}","accessProfiles":[]},"actions":[{"actionId":action,
            "accessProfile":"reviewer","operations":["get-review-context"],"readableInputs":[]}]}});
        let display = json!({"id":ID,"actionId":action,"actionRevision":DIGEST,
            "submissionVersion":1,"revision":1,"effectDigest":DIGEST,"subject":subject,
            "context":{"reference":"native-proposal","contract":contract,"fields":{
                "changes":[],"currentAddressLine":"Synthetic address","facilityId":ID,"supportingDocument":null}},
            "reviewable":true});
        let server = std::thread::spawn(move || {
            for (route, payload) in [
                ("/v1/registry".to_owned(), &metadata),
                ("/v1/registry".to_owned(), &metadata),
                (format!("/v1/proposals/{ID}/review-context"), &display),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let uri = line.split_whitespace().nth(1).unwrap();
                assert_eq!(uri.split('?').next().unwrap(), route);
                loop {
                    line.clear();
                    let bytes = reader.read_line(&mut line).unwrap();
                    if bytes == 0 || line == "\r\n" {
                        break;
                    }
                }
                let body = payload.to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nRegistry-Posture: development\r\nRegistry-Engine-Version: {}\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nCache-Control: no-store\r\nVary: authorization, accept\r\n\r\n{body}", body.len(), registry_platform_buildinfo::DISPLAY_VERSION).unwrap();
            }
        });
        Self {
            runtime,
            identity: ReviewContextIdentity {
                subject: SubjectBinding {
                    source: "facility-registry".into(),
                    subject_type: "proposal".into(),
                    id: ID.into(),
                    version: "1".into(),
                    digest: ContentDigest::parse(DIGEST).unwrap(),
                },
                contract: serde_json::from_value(contract).unwrap(),
            },
            server,
            _root: root,
        }
    }

    pub(crate) async fn assert_policy(
        &self,
        provider: &dyn ReviewContextProvider,
        posture: Posture,
    ) {
        let outcome = provider
            .human_display(HumanDisplayRequest {
                identity: &self.identity,
                source_profile_id: "reviewer",
                credential: EphemeralCredential::new("synthetic-human"),
                include_answers: false,
            })
            .await;
        match posture {
            Posture::Production => {
                assert_eq!(outcome.unwrap_err(), ReviewContextError::VersionUnavailable)
            }
            Posture::Development => assert_eq!(
                outcome.unwrap().display_reference.as_deref(),
                Some("native-proposal")
            ),
        }
    }

    pub(crate) fn finish(self) {
        self.server.join().unwrap();
    }
}
