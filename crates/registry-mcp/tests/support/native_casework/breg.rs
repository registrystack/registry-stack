// SPDX-License-Identifier: Apache-2.0

use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegProposal, BRegRecordFormat, BaseRegistryClient, BaseRegistryClientConfig, BearerToken,
};
use registry_platform_testing::TestAuthorizationServer;
use registry_platform_yaml::Reader;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use url::Url;

use super::{
    casework::SOURCE_PROFILE,
    database::NativeDatabases,
    process::{copy_tree, json_document, operator, private_file, required_binary, ServiceProcess},
    BREG_AUDIENCE, HUMAN_CLIENT, SOURCE_CLIENT, STATUS_CLIENT,
};

const READER_CLIENT: &str = "fixture-reader";
const OPERATOR_CLIENT: &str = "fixture-operator";
const REGISTRAR_CLIENT: &str = "fixture-registrar";
const AUTHOR_CLIENT: &str = "fixture-author";

pub struct Breg {
    pub base_url: Url,
    pub package: PathBuf,
    _process: ServiceProcess,
}

pub struct ProposalFixture {
    pub proposal: BRegProposal,
}

impl Breg {
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        root: &Path,
        fixtures: &Path,
        databases: &NativeDatabases,
        issuer: &TestAuthorizationServer,
        casework_origin: &Url,
        producer_token: &str,
    ) -> Self {
        let ctl = required_binary("BREGCTL_BIN");
        let binary = required_binary("BREG_BIN");
        let project = root.join("project");
        copy_tree(&fixtures.join("products/breg/examples/facility"), &project);
        install_delegated_profile(&project);
        json_document(
            &project.join("tests/journeys.yaml"),
            &json!({
                "apiVersion":"id.registrystack.org/formats/breg/journeys/v1",
                "kind":"BRegJourneys",
                "journeys":[{
                    "id":"native-staff-package",
                    "steps":[{
                        "id":"empty-facility-list",
                        "recordType":"facility",
                        "accessProfile":"facility-reader",
                        "claims":{
                            "principal":"synthetic-reader",
                            "scopes":["registry:facility:read"],
                            "purpose":"facility-administration",
                            "directClaims":{"jurisdiction":"zone-a"}
                        },
                        "request":{"type":"list"},
                        "expect":{"outcome":"success","status":200,"count":0}
                    }]
                }]
            }),
        );
        let test_token = issuer.issue_access_token_with_claims(
            READER_CLIENT,
            "synthetic-reader",
            BREG_AUDIENCE,
            "registry:facility:read",
            super::now() + 300,
            std::collections::BTreeMap::from([
                ("registry_principal".to_owned(), json!("synthetic-reader")),
                (
                    "registry_purpose".to_owned(),
                    json!("facility-administration"),
                ),
                ("jurisdiction".to_owned(), json!("zone-a")),
            ]),
        );
        private_file(&root.join("fixture-token"), test_token.as_bytes());
        json_document(
            &root.join("credentials.yaml"),
            &json!({
                "apiVersion":"id.registrystack.org/formats/breg/schema-test-credentials/v1",
                "kind":"BRegSchemaTestCredentials",
                "bindings":[{"journeyId":"native-staff-package","stepId":"empty-facility-list","credential":{"type":"bearer","tokenRef":"secret:file/fixture-token"}}]
            }),
        );
        let jwks = reqwest::get(issuer.jwks_uri())
            .await
            .expect("read synthetic issuer JWKS")
            .bytes()
            .await
            .expect("synthetic issuer JWKS bytes");
        private_file(&root.join("jwks"), &jwks);
        private_file(
            &root.join("audit-key"),
            b"synthetic-breg-audit-key-0123456789abcdef",
        );
        private_file(
            &root.join("cursor-key"),
            b"synthetic-breg-cursor-key-0123456789abcdef",
        );
        private_file(&root.join("review-token"), producer_token.as_bytes());
        for (name, value) in [
            (
                "breg-test-migration-url",
                &databases.breg_rehearsal_migration,
            ),
            ("breg-test-runtime-url", &databases.breg_rehearsal_runtime),
            ("breg-live-migration-url", &databases.breg_live_migration),
            ("breg-live-runtime-url", &databases.breg_live_runtime),
        ] {
            private_file(&root.join(name), value.as_bytes());
        }
        std::fs::create_dir(root.join("empty-package")).expect("empty BReg rehearsal package");
        let address = super::process::free_address();
        let runtime = |test: bool, package: &Path| {
            let prefix = if test { "breg-test" } else { "breg-live" };
            json!({
                "apiVersion":"id.registrystack.org/formats/breg/runtime/v1alpha1",
                "kind":"BRegRuntimeConfig",
                "listener":{"bind":address.to_string()},
                "identity":{"environment":"test","instanceId":"native-staff-proof","databaseId":format!("native-staff-{prefix}"),"databaseInitializationEnvironment":"test"},
                "secretProviders":{"file":{"root":root}},
                "database":{
                    "runtimeUrlRef":format!("secret:file/{prefix}-runtime-url"),
                    "migrationUrlRef":format!("secret:file/{prefix}-migration-url"),
                    "testOnlyPlaintext":true,
                    "pool":{"maximumConnections":4},
                    "roles":{"migration":databases.breg_roles()[0],"runtime":databases.breg_roles()[1]}
                },
                "package":{"root":package},
                "authentication":{"oidc":{
                    "issuer":issuer.issuer(),"audience":BREG_AUDIENCE,"allowedAlgorithm":"ES256","accessTokenType":"at+jwt",
                    "scopeClaim":"scope","scopeSeparator":" ","allowedClients":[READER_CLIENT,OPERATOR_CLIENT,REGISTRAR_CLIENT,AUTHOR_CLIENT,HUMAN_CLIENT,SOURCE_CLIENT,STATUS_CLIENT],
                    "maximumTokenLifetimeSeconds":3600,"leewayMilliseconds":0,"jwksSource":{"type":"static","documentRef":"secret:file/jwks"}
                },"authorityClaims":{"principal":"registry_principal","purpose":"registry_purpose","trustedActors":{"casework-source-reader":"00000000-0000-4000-8000-0000000000c7"}}},
                "audit":{"hashKeyRef":"secret:file/audit-key","path":root.join("audit/breg.jsonl")},
                "cursor":{"secretRef":"secret:file/cursor-key"},
                "reviewAuthorities":{"casework":{"endpoint":casework_origin.as_str(),"profile":"requester","producerId":"facility-registry","recoveryDays":7,"tokenRef":"secret:file/review-token"}}
            })
        };
        let rehearsal = root.join("rehearsal.yaml");
        json_document(&rehearsal, &runtime(true, &root.join("empty-package")));
        let receipt = root.join("receipt.json");
        operator(
            &ctl,
            &[
                "test".as_ref(),
                project.as_os_str(),
                "--runtime-config".as_ref(),
                rehearsal.as_os_str(),
                "--credentials".as_ref(),
                root.join("credentials.yaml").as_os_str(),
                "--output".as_ref(),
                receipt.as_os_str(),
            ],
            &root.join("test.log"),
        );
        let build = root.join("build");
        operator(
            &ctl,
            &[
                "package".as_ref(),
                project.as_os_str(),
                "--test-receipt".as_ref(),
                receipt.as_os_str(),
                "--output".as_ref(),
                build.as_os_str(),
            ],
            &root.join("package.log"),
        );
        let package = build.join("package");
        let live = root.join("runtime.yaml");
        json_document(&live, &runtime(false, &package));
        operator(
            &ctl,
            &[
                "apply".as_ref(),
                "--runtime-config".as_ref(),
                live.as_os_str(),
                "--package".as_ref(),
                package.as_os_str(),
                "--initial".as_ref(),
            ],
            &root.join("apply.log"),
        );
        let base_url = Url::parse(&format!("http://{address}/")).expect("native BReg URL");
        let process = ServiceProcess::start(
            &binary,
            &["--runtime-config".as_ref(), live.as_os_str()],
            root.join("service.log"),
            base_url.join("ready").expect("BReg readiness URL").as_str(),
        )
        .await;
        Self {
            base_url,
            package,
            _process: process,
        }
    }

    pub async fn create_proposal(
        &self,
        issuer: &TestAuthorizationServer,
        index: u8,
        jurisdiction: &'static str,
    ) -> ProposalFixture {
        let claims = |principal: &str, purpose: &str, jurisdiction: &str| {
            std::collections::BTreeMap::from([
                ("registry_principal".to_owned(), json!(principal)),
                ("registry_purpose".to_owned(), json!(purpose)),
                ("jurisdiction".to_owned(), json!(jurisdiction)),
            ])
        };
        let operator = client(
            &self.base_url,
            issuer.issue_access_token_with_claims(
                OPERATOR_CLIENT,
                "synthetic-operator-editor",
                BREG_AUDIENCE,
                "registry:operator:write",
                super::now() + 300,
                claims(
                    "synthetic-operator-editor",
                    "facility-administration",
                    jurisdiction,
                ),
            ),
        );
        let contract = operator
            .registry_contract(Some("operator-editor"))
            .await
            .expect("read native operator contract")
            .value;
        let BRegDirectWrite::Create(create) = contract
            .select_direct_write("records.operator.create", "operator-editor")
            .expect("select operator create")
        else {
            panic!("operator create is a direct write")
        };
        let operator_id = operator
            .create_record(
                &create,
                &BRegCreateRequest::new(map(json!({"operatorCode":format!("OP-{index}"),"status":"active","jurisdiction":jurisdiction}))).expect("operator request"),
                &key(&format!("native-staff-operator-{index}")),
                BRegRecordFormat::Json,
            )
            .await
            .expect("create native operator")
            .value.data.record_identifier;
        let registrar = client(
            &self.base_url,
            issuer.issue_access_token_with_claims(
                REGISTRAR_CLIENT,
                "synthetic-registrar",
                BREG_AUDIENCE,
                "registry:facility:register",
                super::now() + 300,
                claims(
                    "synthetic-registrar",
                    "facility-administration",
                    jurisdiction,
                ),
            ),
        );
        let contract = registrar
            .registry_contract(Some("facility-registrar"))
            .await
            .expect("registrar contract")
            .value;
        let action = contract
            .select_action("register-facility", "facility-registrar")
            .expect("register action");
        let registered = registrar.invoke_action(
            &action,
            &BRegActionInvocationRequest::new(&action, map(json!({"facilityCode":format!("FAC-{index}"),"name":"Synthetic clinic","addressLine":"1 Synthetic Road","city":"Synthetic City","postalCode":"10000","operatorId":operator_id,"jurisdiction":jurisdiction})), None).expect("register request"),
            &key(&format!("native-staff-register-{index}")),
        ).await.expect("register native facility").value;
        let facility = registered.results()["facility"]
            .record_identifier()
            .to_owned();
        let author = client(
            &self.base_url,
            issuer.issue_access_token_with_claims(
                AUTHOR_CLIENT,
                "synthetic-author",
                BREG_AUDIENCE,
                "registry:facility:correction:submit",
                super::now() + 300,
                claims("synthetic-author", "facility-administration", jurisdiction),
            ),
        );
        let contract = author
            .registry_contract(Some("facility-correction-author"))
            .await
            .expect("author contract")
            .value;
        let action = contract
            .select_action("correct-address", "facility-correction-author")
            .expect("correction action");
        let draft = author.start_proposal(
            &action,
            &BRegActionInvocationRequest::new(&action,map(json!({"facilityId":facility,"addressLine":"2 Synthetic Road","city":"Synthetic City","postalCode":"10001"})),None).expect("proposal request"),
            &key(&format!("native-staff-start-{index}")),
        ).await.expect("start native proposal").value;
        let submit = author
            .prepare_proposal(
                &draft,
                "submit",
                json!({}),
                &key(&format!("native-staff-submit-{index}")),
            )
            .expect("prepare proposal submission");
        let proposal = author
            .execute_proposal(&submit)
            .await
            .expect("submit native proposal")
            .value;
        ProposalFixture { proposal }
    }
}

fn install_delegated_profile(project: &Path) {
    let path = project.join("registry.yaml");
    let bytes = std::fs::read(&path).expect("read copied facility Registry");
    let mut source = Reader::new(path.display().to_string())
        .scan(&bytes)
        .expect("copied facility Registry YAML is valid")
        .expect("copied facility Registry is not empty")
        .to_json_value();
    let profiles = source["accessProfiles"]
        .as_array_mut()
        .expect("facility Registry access profiles");
    let mut delegated = profiles
        .iter()
        .find(|profile| profile["id"] == "proposal-reviewer")
        .expect("facility Registry proposal reviewer")
        .clone();
    delegated["id"] = json!(SOURCE_PROFILE);
    delegated["actorKind"] = json!("agent");
    delegated["requesterClients"] = json!([SOURCE_CLIENT]);
    profiles.retain(|profile| profile["id"] != SOURCE_PROFILE);
    profiles.push(delegated);
    json_document(&path, &source);
}

fn client(base_url: &Url, token: String) -> BaseRegistryClient {
    BaseRegistryClient::new(BaseRegistryClientConfig::new(base_url.clone()))
        .expect("native BReg client")
        .with_bearer_token(BearerToken::new(token).expect("synthetic BReg bearer token"))
}
fn map(value: Value) -> Map<String, Value> {
    value.as_object().expect("fixture object").clone()
}
fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).expect("fixture idempotency key")
}
