// SPDX-License-Identifier: Apache-2.0

use registry_casework_client::{
    AssignmentRequest, BootstrapDirectoryRequest, CaseworkAuth, CaseworkClient,
    CaseworkClientConfig, ContentDigest, DirectoryMember, DirectoryTeamUpdateRequest,
    IssuerPrincipal, ReviewStaffingQuery, ReviewTask, ReviewTaskOwnership,
};
use registry_platform_httputil::client::BearerToken;
use registry_platform_testing::TestAuthorizationServer;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;

use super::{
    breg::ProposalFixture,
    database::NativeDatabases,
    process::{copy_tree, json_document, operator, private_file, required_binary, ServiceProcess},
    BREG_AUDIENCE, CASEWORK_AUDIENCE, HUMAN_IDENTITY_CLAIM, HUMAN_IDENTITY_VALUE,
};

pub const READER_POLICY: &str = "assistant-reader";
pub const SOURCE_PROFILE: &str = "casework-delegated-proposal-reader";
const STAFF_PROFILE: &str = "staff";
const SUPERVISOR_PROFILE: &str = "supervisor";
const ADMIN_PROFILE: &str = "administrator";
const HUMAN_SOURCE_PROFILE: &str = "proposal-reviewer";
const QUEUE: &str = "facility-addresses";
const TEAM: &str = "facility-reviewers";

pub struct Casework {
    pub base_url: Url,
    pub audit_path: PathBuf,
    client: CaseworkClient,
    _process: ServiceProcess,
}

impl Casework {
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        root: &Path,
        fixtures: &Path,
        databases: &NativeDatabases,
        issuer: &TestAuthorizationServer,
        breg_origin: &Url,
        breg_package: &Path,
        address: std::net::SocketAddr,
        status_client_key: &Path,
        source_client_key: &Path,
    ) -> Self {
        let ctl = required_binary("CASEWORKCTL_BIN");
        let binary = required_binary("CASEWORK_BIN");
        let project = root.join("project");
        copy_tree(
            &fixtures.join("products/casework/examples/canonical-review"),
            &project,
        );
        let project_file = project.join("casework.yaml");
        let source = std::fs::read_to_string(&project_file).expect("read copied Casework project");
        assert!(source.contains("https://identity.example.test"));
        private_file(
            &project_file,
            source
                .replace("https://identity.example.test", &issuer.issuer())
                .as_bytes(),
        );
        let bregctl = required_binary("BREGCTL_BIN");
        operator(
            &ctl,
            &[
                "provider".as_ref(),
                "pair".as_ref(),
                project.as_os_str(),
                "--provider-id".as_ref(),
                "facility-proposal-context".as_ref(),
                "--breg-package".as_ref(),
                breg_package.as_os_str(),
                "--action-id".as_ref(),
                "correct-address".as_ref(),
                "--bregctl-bin".as_ref(),
                bregctl.as_os_str(),
                "--apply".as_ref(),
            ],
            &root.join("pair.log"),
        );
        let package = root.join("package");
        operator(
            &ctl,
            &[
                "package".as_ref(),
                project.as_os_str(),
                "--output".as_ref(),
                package.as_os_str(),
                "--revision".as_ref(),
                "native-staff-proof".as_ref(),
            ],
            &root.join("package.log"),
        );
        private_file(
            &root.join("audit-key"),
            b"synthetic-casework-audit-key-0123456789abcd",
        );
        private_file(
            &root.join("casework-database-url"),
            databases.casework.as_bytes(),
        );
        private_file(&root.join("status-client-id"), b"casework-service");
        private_file(&root.join("source-client-id"), b"casework-source-reader");
        std::fs::copy(status_client_key, root.join("status-client-key"))
            .expect("copy fixture status client key");
        std::fs::copy(source_client_key, root.join("source-client-key"))
            .expect("copy fixture source client key");
        let audit_path = root.join("audit/casework.ndjson");
        let runtime = root.join("runtime.yaml");
        json_document(
            &runtime,
            &json!({
                "apiVersion":"id.registrystack.org/formats/casework/runtime/v1alpha1",
                "kind":"CaseworkRuntimeConfig",
                "identity":{"databaseId":"native-staff-proof"},
                "package":{"root":package},
                "listener":{"bind":address.to_string(),"tlsTermination":"development-loopback","networkExposure":"private-address"},
                "secretProviders":{"file":{"root":root}},
                "database":{"runtimeUrlRef":"secret:file/casework-database-url","migrationUrlRef":"secret:file/casework-database-url","testOnlyPlaintext":true},
                "authentication":{"oidc":{
                    "issuer":issuer.issuer(),"audience":CASEWORK_AUDIENCE,"allowInsecureHttp":true,
                    "allowedClients":["registry-mcp","casework-human","facility-registry"],
                    "assertionIssuers":{"registry-mcp":[issuer.issuer()]},
                    "scopeClaim":"scope","humanIdentity":{"claim":HUMAN_IDENTITY_CLAIM,"value":HUMAN_IDENTITY_VALUE},
                    "maximumTokenLifetimeSeconds":300,
                    "delegatedStaffReaders":{
                        READER_POLICY:{
                            "profile":STAFF_PROFILE,"client":"registry-mcp","actorSubject":"registry-mcp",
                            "assertionIssuer":issuer.issuer(),"requiredScope":"casework:staff:delegated-read","maximumTokenLifetimeSeconds":300,
                            "sourceProfiles":[SOURCE_PROFILE]
                        }
                    }
                }},
                "audit":{"path":audit_path,"hashKeyRef":"secret:file/audit-key"},
                "contextProviders":{"facility-registry":{
                    "baseUrl":breg_origin.as_str(),"statusProfile":"casework-review-status","tokenEndpoint":issuer.token_endpoint(),
                    "resource":BREG_AUDIENCE,"scopes":["registry:proposal:review-status"],
                    "clientIdRef":"secret:file/status-client-id","clientAssertionKeyRef":"secret:file/status-client-key",
                    "delegatedDisplayExchange":{
                        "tokenEndpoint":issuer.token_endpoint(),"clientIdRef":"secret:file/source-client-id","clientAssertionKeyRef":"secret:file/source-client-key",
                        "resource":BREG_AUDIENCE,"scopes":["registry:proposal:review"],"generation":"native-staff-proof"
                    }
                }}
            }),
        );
        operator(
            &ctl,
            &[
                "apply".as_ref(),
                "--runtime-config".as_ref(),
                runtime.as_os_str(),
                "--operator-reference".as_ref(),
                "native-staff-proof".as_ref(),
            ],
            &root.join("apply.log"),
        );
        let base_url = Url::parse(&format!("http://{address}/")).expect("native Casework URL");
        let process = ServiceProcess::start(
            &binary,
            &[
                "--runtime-config".as_ref(),
                runtime.as_os_str(),
                "serve".as_ref(),
            ],
            root.join("service.log"),
            base_url
                .join("ready")
                .expect("Casework readiness URL")
                .as_str(),
        )
        .await;
        let client = CaseworkClient::new(CaseworkClientConfig::new(base_url.clone()))
            .expect("native Casework client");
        Self {
            base_url,
            audit_path,
            client,
            _process: process,
        }
    }

    pub async fn bootstrap_staff(
        &self,
        issuer: &TestAuthorizationServer,
        admin_token: &BearerToken,
        alice: &str,
        bob: &str,
        supervisor: &str,
    ) {
        self.client
            .bootstrap_directory(
                CaseworkAuth::new(admin_token, ADMIN_PROFILE),
                0,
                "native-staff-bootstrap",
                &BootstrapDirectoryRequest {
                    team_id: TEAM.to_owned(),
                    staff: vec![
                        IssuerPrincipal {
                            issuer: issuer.issuer(),
                            subject: alice.to_owned(),
                        },
                        IssuerPrincipal {
                            issuer: issuer.issuer(),
                            subject: bob.to_owned(),
                        },
                    ],
                    supervisors: vec![IssuerPrincipal {
                        issuer: issuer.issuer(),
                        subject: supervisor.to_owned(),
                    }],
                    queue_id: QUEUE.to_owned(),
                },
            )
            .await
            .expect("bootstrap native Casework directory");
    }

    pub async fn task_for_proposal(
        &self,
        staff_token: &BearerToken,
        fixture: &ProposalFixture,
    ) -> Uuid {
        let proposal = &fixture.proposal;
        let query = ReviewStaffingQuery {
            ownership: Some(ReviewTaskOwnership::Unclaimed),
            subject_source: Some("facility-registry".to_owned()),
            subject_type: Some("proposal".to_owned()),
            subject_id: Some(proposal.id().to_owned()),
            subject_version: Some(proposal.submission_version().to_string()),
            subject_digest: Some(
                ContentDigest::parse(
                    proposal
                        .effect_digest()
                        .expect("submitted proposal effect digest"),
                )
                .expect("submitted proposal effect digest shape"),
            ),
            limit: Some(10),
            ..ReviewStaffingQuery::default()
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let page = self
                .client
                .review_tasks(
                    CaseworkAuth::new(staff_token, STAFF_PROFILE)
                        .with_source_profile(HUMAN_SOURCE_PROFILE),
                    &query,
                )
                .await
                .expect("find BReg-created native task")
                .value;
            match page.items.as_slice() {
                [task] => return task.task_id,
                [] if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                items => panic!("exactly one BReg-created task is visible: {items:?}"),
            }
        }
    }

    pub async fn claim(&self, staff_token: &BearerToken, task_id: Uuid, key: &str) -> ReviewTask {
        let current = self
            .client
            .review_task(
                CaseworkAuth::new(staff_token, STAFF_PROFILE)
                    .with_source_profile(HUMAN_SOURCE_PROFILE),
                task_id,
            )
            .await
            .expect("read unclaimed task")
            .value;
        self.client
            .claim_review_task(
                CaseworkAuth::new(staff_token, STAFF_PROFILE)
                    .with_source_profile(HUMAN_SOURCE_PROFILE),
                task_id,
                current.revision,
                key,
            )
            .await
            .expect("claim native task")
            .value
    }

    pub async fn transfer(
        &self,
        issuer: &TestAuthorizationServer,
        supervisor_token: &BearerToken,
        holder_token: &BearerToken,
        task_id: Uuid,
        assignee: &str,
    ) -> ReviewTask {
        let current = self
            .client
            .review_task(
                CaseworkAuth::new(holder_token, STAFF_PROFILE)
                    .with_source_profile(HUMAN_SOURCE_PROFILE),
                task_id,
            )
            .await
            .expect("read held task before transfer")
            .value;
        self.client
            .assign_review_task(
                CaseworkAuth::new(supervisor_token, SUPERVISOR_PROFILE)
                    .with_source_profile(HUMAN_SOURCE_PROFILE),
                task_id,
                current.revision,
                "native-staff-transfer-to-bob",
                &AssignmentRequest {
                    assignee: IssuerPrincipal {
                        issuer: issuer.issuer(),
                        subject: assignee.to_owned(),
                    },
                    reason: Some("Balance the synthetic review queue".to_owned()),
                },
            )
            .await
            .expect("transfer native task through maintained Casework client")
            .value
    }

    pub async fn remove_alice(
        &self,
        issuer: &TestAuthorizationServer,
        admin_token: &BearerToken,
        _alice: &str,
        bob: &str,
    ) {
        let directory = self
            .client
            .directory(CaseworkAuth::new(admin_token, ADMIN_PROFILE))
            .await
            .expect("read native directory")
            .value;
        let team = directory
            .teams
            .iter()
            .find(|team| team.id == TEAM)
            .expect("native team");
        self.client
            .update_directory_team(
                CaseworkAuth::new(admin_token, ADMIN_PROFILE),
                TEAM,
                directory.revision,
                "native-staff-revoke-alice",
                &DirectoryTeamUpdateRequest {
                    staff: vec![DirectoryMember {
                        issuer: issuer.issuer(),
                        subject: bob.to_owned(),
                        display_name: None,
                    }],
                    supervisors: team.supervisors.clone(),
                    served_queues: team.served_queues.clone(),
                },
            )
            .await
            .expect("remove Alice's current team membership");
    }
}
