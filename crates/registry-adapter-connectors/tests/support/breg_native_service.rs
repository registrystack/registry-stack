// SPDX-License-Identifier: Apache-2.0
//! A separately built BReg service for the connector's native tests,
//! following the coordinator's own native BReg fixture: owned disposable
//! databases and roles, migration through the operator, and a packaged
//! project whose writer profile covers the connector's families. Only
//! fixture-owned databases and roles are provisioned or removed here.

#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use registry_breg_client::{
    BRegListRequest, BRegRecordOptions, BaseRegistryClient, BaseRegistryClientConfig, StaticToken,
    TokenProvider,
};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use registry_platform_testing::{fixtures, TestActorKind, TestAuthorizationServer, TestClient};
use serde_json::{json, Value};

fn binary(variable: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
        panic!("{variable} is required; run products/adapter/scripts/test-connector-native.py")
    }));
    assert!(
        path.is_file(),
        "{variable} must name an existing executable"
    );
    path
}

fn spatial_bbox_role(runtime_role: &str) -> String {
    let candidate = format!("{runtime_role}__spatial_bbox");
    assert!(
        candidate.len() <= 63,
        "the fixture spatial role must fit PostgreSQL's identifier bound"
    );
    candidate
}

/// A synthetic issuer whose service actor has the BReg fixture's writer
/// authority. Cross-crate native tests use the same identity setup as
/// the connector's own native suite.
pub async fn issuer(subject: &str) -> TestAuthorizationServer {
    let (_, reader_public) = fixtures::ed25519_pair();
    let (_, ingestion_public) = fixtures::ed25519_pair();
    TestAuthorizationServer::builder()
        .with_signing_key(generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap())
        .client(
            TestClient::new("application-reader")
                .with_public_jwk(reader_public)
                .with_resource("urn:example:applications")
                .with_actor_kind(TestActorKind::Service)
                .with_service_subject(subject),
        )
        .client(
            TestClient::new("adapter-field-ingestion")
                .with_public_jwk(ingestion_public)
                .with_resource("urn:example:applications")
                .with_actor_kind(TestActorKind::Service)
                .with_service_subject("adapter-field-ingestion"),
        )
        .start()
        .await
}

/// A token provider for one synthetic service actor admitted by
/// [`issuer`]. The provider is host-owned and never enters prepared
/// connector bytes.
pub fn token_provider(issuer: &TestAuthorizationServer, subject: &str) -> Arc<dyn TokenProvider> {
    let token = issuer.issue_access_token(
        "application-reader",
        subject,
        "urn:example:applications",
        "applications:read",
        chrono::Utc::now().timestamp() + 3600,
    );
    Arc::new(StaticToken::new(token).expect("the synthetic token is valid"))
}

/// A token provider for the QField fixture's narrowly admitted ingestion
/// service. It intentionally differs from the fixture's observer client.
pub fn field_ingestion_token_provider(issuer: &TestAuthorizationServer) -> Arc<dyn TokenProvider> {
    let token = issuer.issue_access_token(
        "adapter-field-ingestion",
        "adapter-field-ingestion",
        "urn:example:applications",
        "registry:write",
        chrono::Utc::now().timestamp() + 3600,
    );
    Arc::new(StaticToken::new(token).expect("the synthetic ingestion token is valid"))
}

fn operator(binary: &Path, args: &[&std::ffi::OsStr], log: &Path) -> Value {
    let output = Command::new(binary)
        .args(["--format", "json"])
        .args(args)
        .output()
        .expect("independent BReg operator starts");
    let report_bytes = output.stdout.clone();
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    private_file(log, &bytes);
    assert!(
        output.status.success(),
        "BReg operator failed; inspect {}",
        log.display()
    );
    serde_json::from_slice(&report_bytes).expect("BReg operator JSON report")
}

fn document(path: &Path, value: Value) {
    private_file(path, serde_norway::to_string(&value).unwrap().as_bytes());
}

fn private_file(path: &Path, contents: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("fixture directory");
    }
    std::fs::write(path, contents).expect("fixture file contents");
    // The secret providers refuse world-readable material.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("fixture file permissions");
}

pub struct Breg {
    pub root: PathBuf,
    pub base_url: String,
    package_revision: String,
    schema_fingerprint: String,
    admin_url: String,
    databases: [String; 2],
    roles: [String; 2],
    spatial_role: Option<String>,
    child: Option<Child>,
}

impl Breg {
    pub async fn start(issuer: &TestAuthorizationServer) -> Self {
        Self::start_inner(issuer, None).await
    }

    /// Start the native BReg fixture with the maintained QField field-site
    /// registry added. Only this opt-in variant provisions PostGIS.
    pub async fn start_with_field_site(
        issuer: &TestAuthorizationServer,
        field_site_registry: Value,
    ) -> Self {
        Self::start_inner(issuer, Some(field_site_registry)).await
    }

    async fn start_inner(
        issuer: &TestAuthorizationServer,
        field_site_registry: Option<Value>,
    ) -> Self {
        let field_site = field_site_registry.is_some();
        let ctl = binary("ADAPTER_BREGCTL_BIN");
        let runtime_binary = binary("ADAPTER_BREG_BIN");
        let admin_url =
            std::env::var("ADAPTER_TEST_DATABASE_URL").expect("ADAPTER_TEST_DATABASE_URL is required; run products/adapter/scripts/test-connector-native.py");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        // Private logs stay on failure; a passing fixture removes the tree.
        let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap()
            .keep();
        let runtime_role = if field_site {
            format!("adapter_br_{suffix}")
        } else {
            format!("adapter_breg_runtime_{suffix}")
        };
        let spatial_role = field_site.then(|| spatial_bbox_role(&runtime_role));
        let mut service = Self {
            root,
            base_url: String::new(),
            package_revision: String::new(),
            schema_fingerprint: String::new(),
            admin_url,
            databases: [
                format!("adapter_breg_test_{suffix}"),
                format!("adapter_breg_live_{suffix}"),
            ],
            roles: [format!("adapter_breg_migrate_{suffix}"), runtime_role],
            spatial_role,
            child: None,
        };
        let password = uuid::Uuid::new_v4().simple().to_string();
        let (admin, connection) =
            tokio_postgres::connect(&service.admin_url, tokio_postgres::NoTls)
                .await
                .unwrap();
        let root_connection = tokio::spawn(connection);
        for role in &service.roles {
            admin
                .batch_execute(&format!(
                    "CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}'"
                ))
                .await
                .expect("fixture administrator creates owned role");
        }
        for (index, database) in service.databases.iter().enumerate() {
            admin
                .batch_execute(&format!("CREATE DATABASE {database}"))
                .await
                .unwrap();
            let mut url = url::Url::parse(&service.admin_url).unwrap();
            url.set_path(&format!("/{database}"));
            let (owner, connection) = tokio_postgres::connect(url.as_str(), tokio_postgres::NoTls)
                .await
                .unwrap();
            let database_connection = tokio::spawn(connection);
            if field_site {
                let spatial_role = service
                    .spatial_role
                    .as_deref()
                    .expect("the QField fixture has a spatial role");
                owner
                    .batch_execute(&format!(
                        "CREATE SCHEMA IF NOT EXISTS registry_spatial_ext; \
                         REVOKE ALL ON SCHEMA registry_spatial_ext FROM PUBLIC; \
                         CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA registry_spatial_ext; \
                         GRANT USAGE ON SCHEMA registry_spatial_ext TO {}, {}; \
                         DO $breg_spatial$ BEGIN \
                           IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{spatial_role}') THEN \
                             CREATE ROLE {spatial_role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; \
                           END IF; \
                         END $breg_spatial$; \
                         GRANT {spatial_role} TO {} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE; \
                         GRANT USAGE ON SCHEMA registry_spatial_ext TO {spatial_role}",
                        service.roles[0], service.roles[1], service.roles[0]
                    ))
                    .await
                    .expect("the QField BReg fixture provisions PostGIS");
            }
            owner.batch_execute(&format!(
                "REVOKE ALL ON DATABASE {database} FROM PUBLIC; GRANT CONNECT, TEMPORARY ON DATABASE {database} TO {}; GRANT CONNECT ON DATABASE {database} TO {}",
                service.roles[0], service.roles[1]
            )).await.unwrap();
            // Deployment provisioning, not BReg runtime behavior; it
            // follows BReg postgres::roles::provision_managed_schemas.
            for schema in [
                "registry_internal",
                "registry_data",
                "registry_source",
                "registry_derived",
                "registry_context",
            ] {
                owner
                    .batch_execute(&format!(
                        "CREATE SCHEMA {schema} AUTHORIZATION {}; REVOKE ALL ON SCHEMA {schema} FROM PUBLIC",
                        service.roles[0]
                    ))
                    .await
                    .unwrap();
            }
            database_connection.abort();
            for (role_index, role) in service.roles.iter().enumerate() {
                url.set_username(role).unwrap();
                url.set_password(Some(&password)).unwrap();
                private_file(
                    &service.root.join(format!("database-{index}-{role_index}")),
                    url.as_str().as_bytes(),
                );
            }
        }
        root_connection.abort();
        let project = service.root.join("project");
        std::fs::create_dir_all(project.join("tests")).unwrap();
        std::fs::create_dir_all(project.join("scripts")).unwrap();
        private_file(
            &service.root.join("audit-key"),
            b"synthetic-audit-key-of-at-least-32-bytes",
        );
        private_file(
            &service.root.join("cursor-key"),
            b"synthetic-cursor-key-of-at-least-32-bytes",
        );
        let jwks = reqwest::get(issuer.jwks_uri())
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        private_file(&service.root.join("jwks"), &jwks);
        let token = issuer.issue_access_token(
            "application-reader",
            "connector-reader",
            "urn:example:applications",
            "applications:read",
            chrono::Utc::now().timestamp() + 3600,
        );
        private_file(&service.root.join("fixture-token"), token.as_bytes());
        let mut registry = json!({
            "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
            "kind": "BRegProject",
            "project": {
                "id": "adapter-connector-proof",
                "canonicalBaseIri": "https://synthetic.example.test/connector-proof",
                "version": "1",
                "defaultLanguage": "en"
            },
            "package": {"sourceRevision": "adapter-native-connector-proof"},
            "recordTypes": [
                {
                    "id": "item",
                    "primaryDataset": "synthetic-items",
                    "route": "items",
                    "mutationMode": "mutable",
                    "classification": "internal",
                    "batch": {"maximumItems": 100, "maximumBytes": 65536},
                    "fields": [
                        {"id": "owner", "type": "string", "required": true, "maximumLength": 80, "classification": "internal"},
                        {"id": "label", "type": "string", "required": true, "minimumLength": 1, "maximumLength": 80, "classification": "internal"}
                    ]
                },
                {
                    "id": "household",
                    "primaryDataset": "synthetic-items",
                    "route": "households",
                    "mutationMode": "mutable",
                    "classification": "internal",
                    "fields": [
                        {"id": "owner", "type": "string", "required": true, "maximumLength": 80, "classification": "internal"},
                        {"id": "source-submission-id", "apiName": "sourceSubmissionId", "type": "string", "required": true, "minimumLength": 1, "maximumLength": 128, "classification": "internal"},
                        {"id": "respondent-name", "apiName": "respondentName", "type": "string", "required": true, "minimumLength": 1, "maximumLength": 256, "classification": "internal"},
                        {"id": "household-size", "apiName": "householdSize", "type": "int64", "required": true, "classification": "internal"}
                    ],
                    "selectorProfiles": [
                        {"id": "by-source-submission", "fields": ["source-submission-id"]}
                    ]
                }
            ],
            "datasets": [{"id": "synthetic-items"}],
            "functions": [
                {
                    "id": "update-item-plan",
                    "runtime": "rhai",
                    "source": "scripts/update-item.rhai",
                    "entrypoint": "plan",
                    "abi": "registry.action-plan/v1"
                },
                {
                    "id": "register-household-plan",
                    "runtime": "rhai",
                    "source": "scripts/register-household.rhai",
                    "entrypoint": "plan",
                    "abi": "registry.action-plan/v1"
                }
            ],
            "actions": [
                {
                    "id": "update-item",
                    "execution": {"mode": "immediate"},
                    "inputs": [
                        {"id": "target", "apiName": "targetId", "type": "reference", "target": "item", "required": true, "classification": "internal"},
                        {"id": "label", "type": "string", "required": true, "minimumLength": 1, "maximumLength": 80, "classification": "internal"}
                    ],
                    "plan": {
                        "type": "function",
                        "function": "update-item-plan",
                        "inputs": ["target", "label"],
                        "writes": [{"id": "item", "target": {"fromInput": "target"}, "operation": "patch", "fields": ["label"]}]
                    }
                },
                {
                    "id": "propose-item",
                    "execution": {"mode": "proposal", "proposal": {"review": {"type": "none"}, "retention": {"mode": "operator-erase"}}},
                    "inputs": [
                        {"id": "target", "apiName": "targetId", "type": "reference", "target": "item", "required": true, "classification": "internal"},
                        {"id": "label", "type": "string", "required": true, "minimumLength": 1, "maximumLength": 80, "classification": "internal"}
                    ],
                    "commitGuards": {"targets": [{"input": "target", "revision": "unchanged"}]},
                    "plan": {"type": "fixed", "effects": [{"id": "item", "target": {"fromInput": "target"}, "operation": "patch", "set": {"label": {"fromInput": "label"}}}]}
                },
                {
                    "id": "manual-item",
                    "execution": {"mode": "proposal", "proposal": {"review": {"type": "none"}, "retention": {"mode": "operator-erase"}, "application": {"mode": "manual"}}},
                    "inputs": [
                        {"id": "target", "apiName": "targetId", "type": "reference", "target": "item", "required": true, "classification": "internal"},
                        {"id": "label", "type": "string", "required": true, "minimumLength": 1, "maximumLength": 80, "classification": "internal"}
                    ],
                    "commitGuards": {"targets": [{"input": "target", "revision": "unchanged"}]},
                    "plan": {"type": "fixed", "effects": [{"id": "item", "target": {"fromInput": "target"}, "operation": "patch", "set": {"label": {"fromInput": "label"}}}]}
                },
                {
                    "id": "register-household",
                    "execution": {"mode": "proposal", "proposal": {"review": {"type": "none"}, "retention": {"mode": "operator-erase"}}},
                    "inputs": [
                        {"id": "source-submission-id", "apiName": "sourceSubmissionId", "type": "string", "required": true, "minimumLength": 1, "maximumLength": 128, "classification": "internal"},
                        {"id": "respondent-name", "apiName": "respondentName", "type": "string", "required": true, "minimumLength": 1, "maximumLength": 256, "classification": "internal"},
                        {"id": "household-size", "apiName": "householdSize", "type": "int64", "required": true, "classification": "internal"}
                    ],
                    "plan": {
                        "type": "function",
                        "function": "register-household-plan",
                        "inputs": ["source-submission-id", "respondent-name", "household-size"],
                        "writes": [{"id": "household", "target": {"recordType": "household"}, "operation": "create", "fields": ["owner", "source-submission-id", "respondent-name", "household-size"]}]
                    }
                }
            ],
            "accessProfiles": [{
                "id": "writer",
                "default": true,
                "principalClaim": "sub",
                "requiredScopes": ["applications:read"],
                "actorKind": "service",
                "requesterClients": ["application-reader"],
                "permissions": {
                    "records": [
                        {
                            "recordType": "item",
                            "operations": ["create", "get", "list", "patch", "batch", "revisions", "snapshot"],
                            "readableFields": ["owner", "label"],
                            "writableFields": ["owner", "label"],
                            "revisionAccess": true,
                            "rowBoundaries": [{"field": "owner", "claim": "sub", "operator": "equals"}]
                        },
                        {
                            "recordType": "household",
                            "operations": ["create", "get", "list", "lookup"],
                            "readableFields": ["owner", "source-submission-id", "respondent-name", "household-size"],
                            "writableFields": ["owner", "source-submission-id", "respondent-name", "household-size"],
                            "filterableFields": ["source-submission-id"],
                            "lookups": [{"selector": "by-source-submission", "valueOrigin": "request"}],
                            "rowBoundaries": [{"field": "owner", "claim": "sub", "operator": "equals"}]
                        }
                    ],
                    "actions": [
                        {"action": "update-item", "operations": ["invoke"], "targets": [{"recordType": "item", "rowBoundaries": [{"field": "owner", "claim": "sub", "operator": "equals"}]}], "results": ["item"]},
                        {"action": "propose-item", "operations": ["start"], "targets": [{"recordType": "item", "rowBoundaries": [{"field": "owner", "claim": "sub", "operator": "equals"}]}]},
                        {"action": "manual-item", "operations": ["start"], "targets": [{"recordType": "item", "rowBoundaries": [{"field": "owner", "claim": "sub", "operator": "equals"}]}]},
                        {"action": "register-household", "operations": ["start"], "targets": [{"recordType": "household", "rowBoundaries": [{"field": "owner", "claim": "sub", "operator": "equals"}]}]}
                    ],
                    "proposals": [
                        {"action": "propose-item", "operations": ["get", "submit"], "ownership": "caller", "targets": [{"recordType": "item", "rowBoundaries": [{"field": "owner", "claim": "sub", "operator": "equals"}]}]},
                        {"action": "manual-item", "operations": ["get", "submit", "apply"], "ownership": "caller", "targets": [{"recordType": "item", "rowBoundaries": [{"field": "owner", "claim": "sub", "operator": "equals"}]}]},
                        {"action": "register-household", "operations": ["get", "submit"], "ownership": "caller", "targets": [{"recordType": "household", "rowBoundaries": [{"field": "owner", "claim": "sub", "operator": "equals"}]}]}
                    ]
                }
            }]
        });
        if let Some(qfield) = field_site_registry {
            for record_type in registry["recordTypes"]
                .as_array_mut()
                .expect("the native record types are an array")
            {
                let owner = record_type["fields"]
                    .as_array_mut()
                    .expect("the native fields are an array")
                    .iter_mut()
                    .find(|field| field["id"] == "owner")
                    .expect("the native record type has an owner field");
                owner["minimumLength"] = json!(1);
                owner["maximumLength"] = json!(128);
            }
            for section in ["datasets", "recordTypes", "actions", "accessProfiles"] {
                registry[section]
                    .as_array_mut()
                    .expect("the native registry section is an array")
                    .extend(
                        qfield[section]
                            .as_array()
                            .expect("the QField registry section is an array")
                            .iter()
                            .cloned(),
                    );
            }
            registry["accessProfiles"][0]["permissions"]["records"]
                .as_array_mut()
                .expect("the fixture observer record grants are an array")
                .push(json!({
                    "recordType": "field-site",
                    "operations": ["get", "list"],
                    "readableFields": ["owner", "source-submission-id", "site-name", "position", "boundary", "contacts"],
                    "rowBoundaries": "unrestricted"
                }));
        }
        document(&project.join("registry.yaml"), registry);
        private_file(
            &project.join("scripts/update-item.rhai"),
            br#"fn plan(ctx) {
    #{effects: [#{id: "item", set: #{label: ctx.inputs.label}}]}
}
"#,
        );
        private_file(
            &project.join("scripts/register-household.rhai"),
            br#"fn plan(ctx) {
    #{effects: [#{
        id: "household",
        set: #{
            owner: "adapter-job-native",
            "source-submission-id": ctx.inputs["source-submission-id"],
            "respondent-name": ctx.inputs["respondent-name"],
            "household-size": ctx.inputs["household-size"]
        }
    }]}
}
"#,
        );
        operator(
            &ctl,
            &[
                "generate".as_ref(),
                "actions".as_ref(),
                project.as_os_str(),
                "--output".as_ref(),
                service.root.join("action-contracts").as_os_str(),
            ],
            &service.root.join("action-contracts.log"),
        );
        document(
            &project.join("tests/journeys.yaml"),
            json!({
                "apiVersion": "id.registrystack.org/formats/breg/journeys/v1",
                "kind": "BRegJourneys",
                "journeys": [{
                    "id": "fixture-empty",
                    "steps": [{
                        "id": "list",
                        "recordType": "item",
                        "accessProfile": "writer",
                        "claims": {
                            "principal": "connector-reader",
                            "scopes": ["applications:read"],
                            "actorKind": "service",
                            "requesterClient": "application-reader",
                            "directClaims": {"sub": "connector-reader"}
                        },
                        "request": {"type": "list"},
                        "expect": {"outcome": "success", "status": 200, "count": 0}
                    }]
                }]
            }),
        );
        document(
            &service.root.join("credentials.yaml"),
            json!({
                "apiVersion": "id.registrystack.org/formats/breg/schema-test-credentials/v1",
                "kind": "BRegSchemaTestCredentials",
                "bindings": [{
                    "journeyId": "fixture-empty",
                    "stepId": "list",
                    "credential": {"type": "bearer", "tokenRef": "secret:file/fixture-token"}
                }]
            }),
        );
        std::fs::create_dir(service.root.join("empty-package")).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let runtime = |database: usize, package: &Path| {
            json!({
                "apiVersion": "id.registrystack.org/formats/breg/runtime/v1alpha1",
                "kind": "BRegRuntimeConfig",
                "listener": {"bind": address.to_string()},
                "identity": {
                    "environment": "test",
                    "instanceId": "adapter-connector-proof",
                    "databaseId": "adapter-connector-proof",
                    "databaseInitializationEnvironment": "test"
                },
                "secretProviders": {"file": {"root": service.root}},
                "database": {
                    "runtimeUrlRef": format!("secret:file/database-{database}-1"),
                    "migrationUrlRef": format!("secret:file/database-{database}-0"),
                    "testOnlyPlaintext": true,
                    "pool": {"maximumConnections": 4},
                    "roles": {"migration": service.roles[0], "runtime": service.roles[1]}
                },
                "package": {"root": package},
                "authentication": {
                    "oidc": {
                        "issuer": issuer.issuer(),
                        "audience": "urn:example:applications",
                        "allowedAlgorithm": "ES256",
                        "accessTokenType": "at+jwt",
                        "scopeClaim": "scope",
                        "scopeSeparator": " ",
                        "allowedClients": ["application-reader", "adapter-field-ingestion"],
                        "maximumTokenLifetimeSeconds": 3600,
                        "leewayMilliseconds": 0,
                        "jwksSource": {"type": "static", "documentRef": "secret:file/jwks"}
                    },
                    "authorityClaims": {"principal": "sub"}
                },
                "audit": {
                    "hashKeyRef": "secret:file/audit-key",
                    "path": service.root.join("audit/breg.jsonl")
                },
                "cursor": {"secretRef": "secret:file/cursor-key"}
            })
        };
        let rehearsal = service.root.join("rehearsal.yaml");
        document(&rehearsal, runtime(0, &service.root.join("empty-package")));
        let receipt = service.root.join("receipt.json");
        operator(
            &ctl,
            &[
                "test".as_ref(),
                project.as_os_str(),
                "--runtime-config".as_ref(),
                rehearsal.as_os_str(),
                "--credentials".as_ref(),
                service.root.join("credentials.yaml").as_os_str(),
                "--output".as_ref(),
                receipt.as_os_str(),
            ],
            &service.root.join("test.log"),
        );
        let build = service.root.join("build");
        let package_report = operator(
            &ctl,
            &[
                "package".as_ref(),
                project.as_os_str(),
                "--test-receipt".as_ref(),
                receipt.as_os_str(),
                "--output".as_ref(),
                build.as_os_str(),
            ],
            &service.root.join("package.log"),
        );
        service.package_revision = package_report
            .get("packageDigest")
            .and_then(Value::as_str)
            .expect("package report carries its digest")
            .to_owned();
        let live = service.root.join("live.yaml");
        let package = build.join("package");
        let package_manifest: Value = serde_json::from_slice(
            &std::fs::read(package.join("package.json")).expect("built package manifest"),
        )
        .expect("built package manifest is JSON");
        service.schema_fingerprint = package_manifest
            .pointer("/manifest/schemaFingerprint")
            .and_then(Value::as_str)
            .expect("built package carries its schema fingerprint")
            .to_owned();
        document(&live, runtime(1, &package));
        drop(listener);
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
            &service.root.join("apply.log"),
        );
        let log_path = service.root.join("service.log");
        private_file(&log_path, b"");
        let log = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        service.child = Some(
            Command::new(runtime_binary)
                .arg("--runtime-config")
                .arg(live)
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        );
        service.base_url = format!("http://{address}");
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                service
                    .child
                    .as_mut()
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_none(),
                "BReg exited; inspect {}",
                log_path.display()
            );
            if http
                .get(format!("{}/ready", service.base_url))
                .timeout(Duration::from_secs(2))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "BReg not ready; inspect {}",
                log_path.display()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        service
    }

    /// A token-backed client for one observation the connector itself does
    /// not carry.
    pub fn client(&self, issuer: &TestAuthorizationServer) -> BaseRegistryClient {
        let token = issuer.issue_access_token(
            "application-reader",
            "connector-reader",
            "urn:example:applications",
            "applications:read",
            chrono::Utc::now().timestamp() + 3600,
        );
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(self.base_url.parse().unwrap())
                .with_token_provider(std::sync::Arc::new(StaticToken::new(token).unwrap()))
                .with_maximum_mutation_retries(0),
        )
        .unwrap()
    }

    /// Read one ingested field site through a fixture-only observer grant.
    /// The QField ingestion profile itself intentionally has no Record CRUD.
    pub async fn field_site(
        &self,
        issuer: &TestAuthorizationServer,
        source_submission_id: &str,
    ) -> Value {
        let options = BRegRecordOptions::default()
            .access_profile("writer")
            .expect("the observer profile is valid");
        let request = BRegListRequest::default()
            .options(options)
            .top(100)
            .expect("the fixture page bound is valid");
        let client = self.client(issuer);
        for _ in 0..100 {
            let records = client
                .list_records("field-sites", &request)
                .await
                .expect("the ingested field sites are observable");
            if let Some(record) = records.value.value.items.into_iter().find(|record| {
                record.domain_data.get("sourceSubmissionId")
                    == Some(&Value::String(source_submission_id.to_owned()))
            }) {
                return serde_json::to_value(record.domain_data)
                    .expect("the field-site data renders as JSON");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the requested field site did not become visible")
    }

    /// The deployment origin the connector's configuration names.
    pub fn origin(&self) -> String {
        self.base_url.clone()
    }

    /// The operator-produced Action contract from the exact package the
    /// native service is running. Composition fixtures pass these bytes to
    /// another product instead of reconstructing a contract from client
    /// metadata.
    pub fn action_contract(&self) -> Value {
        serde_json::from_slice(
            &std::fs::read(
                self.root
                    .join("action-contracts/generated/action-contracts.json"),
            )
            .expect("the packaged Action contract exists"),
        )
        .expect("the packaged Action contract is JSON")
    }

    /// The operator-built package digest the active ingestion contract names
    /// as its package revision.
    pub fn package_revision(&self) -> &str {
        &self.package_revision
    }

    /// The operator-built package fingerprint that apply verified against
    /// the installed managed schema.
    pub fn schema_fingerprint(&self) -> &str {
        &self.schema_fingerprint
    }

    pub fn finish(self) {
        let root = self.root.clone();
        drop(self);
        std::fs::remove_dir_all(root).unwrap();
    }
}

impl Drop for Breg {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let admin_url = self.admin_url.clone();
        let databases = self.databases.clone();
        let roles = self.roles.clone();
        let spatial_role = self.spatial_role.clone();
        // Cleanup also runs on assertion failure, on a separate runtime
        // because Drop can run inside Tokio. FORCE targets only generated
        // fixture databases.
        let result = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let (admin, connection) =
                        tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await?;
                    let task = tokio::spawn(connection);
                    for database in databases {
                        admin
                            .batch_execute(&format!(
                                "DROP DATABASE IF EXISTS {database} WITH (FORCE)"
                            ))
                            .await?;
                    }
                    if let Some(role) = spatial_role.as_deref() {
                        admin
                            .batch_execute(&format!("REVOKE {role} FROM {}", roles[0]))
                            .await?;
                    }
                    for role in roles {
                        admin
                            .batch_execute(&format!("DROP ROLE IF EXISTS {role}"))
                            .await?;
                    }
                    if let Some(role) = spatial_role {
                        admin
                            .batch_execute(&format!("DROP ROLE IF EXISTS {role}"))
                            .await?;
                    }
                    task.abort();
                    Ok::<(), tokio_postgres::Error>(())
                })
        })
        .join();
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("fixture-owned BReg database cleanup failed");
        }
    }
}
