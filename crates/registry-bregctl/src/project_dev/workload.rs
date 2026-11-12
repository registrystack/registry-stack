// SPDX-License-Identifier: Apache-2.0
//! Runner-owned Python workload connections and rotating short-lived tokens.

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

use super::{
    issuer::{self, Issuer},
    plan::{Product, TestPerson},
    private_directory, write_private, RunInput,
};

pub(super) const CONNECTION_FORMAT: &str =
    "id.registrystack.org/formats/platform/python-connection/v1alpha1";
pub(super) const CONNECTION_KIND: &str = "PlatformPythonConnection";
pub(super) const TOKEN_FORMAT: &str =
    "id.registrystack.org/formats/platform/dev-workload-token/v1alpha1";
pub(super) const TOKEN_KIND: &str = "PlatformDevWorkloadToken";
const CONNECTION_FILE: &str = "python-connection.json";
const DIRECTORY: &str = "python-workload";
const ROTATION_SECONDS: u64 = 60;

/// Live credentials owned by the existing run supervisor, not a second broker.
pub(super) struct WorkloadCredentials {
    root: PathBuf,
    input: Arc<RunInput>,
    issuer: Arc<Issuer>,
    urls: BTreeMap<Product, String>,
    generation: u64,
    next_rotation: u64,
    run_expires: u64,
}

impl WorkloadCredentials {
    pub(super) fn prepare(
        root: &Path,
        input: Arc<RunInput>,
        issuer: Arc<Issuer>,
        urls: &BTreeMap<Product, String>,
        now: u64,
        run_expires: u64,
    ) -> Result<Option<Self>> {
        if input.plan.workloads.is_empty() {
            return Ok(None);
        }
        ensure!(now < run_expires, "the development run has expired");
        let root = root.join(DIRECTORY);
        private_directory(&root).context("cannot create private Python workload state")?;
        let mut credentials = Self {
            root,
            input,
            issuer,
            urls: urls.clone(),
            generation: 0,
            next_rotation: now,
            run_expires,
        };
        credentials.rotate(now)?;
        let connection = credentials.connection_document()?;
        write_private(
            &credentials.root.join(CONNECTION_FILE),
            &serde_json::to_vec(&connection)?,
        )?;
        Ok(Some(credentials))
    }

    pub(super) fn path(&self) -> PathBuf {
        self.root.join(CONNECTION_FILE)
    }

    /// Replace each binding's complete token envelope once it is due. Every
    /// envelope retains the run expiry; rotation cannot renew the run.
    pub(super) fn rotate_if_due(&mut self, now: u64) -> Result<()> {
        if now >= self.next_rotation && now < self.run_expires {
            self.rotate(now)?;
        }
        Ok(())
    }

    /// Revoke the file handoff before product cleanup starts. The replacement
    /// is complete JSON but deliberately has no token, so a reader cannot use
    /// the previous generation during the shutdown window.
    pub(super) fn invalidate(&mut self, now: u64) -> Result<()> {
        let generation = self
            .generation
            .checked_add(1)
            .context("workload token generation overflow")?;
        for (name, workload) in &self.input.plan.workloads {
            let state = json!({
                "apiVersion": TOKEN_FORMAT,
                "kind": TOKEN_KIND,
                "status": "stopped",
                "runId": self.input.run_id,
                "binding": name,
                "product": workload.product,
                "issuer": self.input.plan.issuer,
                "subject": workload.subject,
                "clientId": workload.client,
                "profile": workload.grant.profile,
                "resource": self.input.plan.product(workload.product).audience,
                "scopes": workload.grant.scopes,
                "claims": workload.grant.claims,
                "generation": generation,
                "issuedAt": now.min(self.run_expires),
                "expiresAt": now.min(self.run_expires),
                "runExpiresAt": self.run_expires,
            });
            write_private(
                &self.root.join(token_file(name)),
                &serde_json::to_vec(&state)?,
            )?;
        }
        self.generation = generation;
        self.next_rotation = self.run_expires;
        Ok(())
    }

    fn rotate(&mut self, now: u64) -> Result<()> {
        let generation = self
            .generation
            .checked_add(1)
            .context("workload token generation overflow")?;
        // Reserve the generation before writing any binding. If one later
        // binding fails, a retry skips forward instead of changing an already
        // observed file under the same generation number.
        self.generation = generation;
        let expires_at = issuer::token_expiry(self.run_expires, now);
        ensure!(expires_at > now, "the development run has expired");
        for (name, workload) in &self.input.plan.workloads {
            let person = TestPerson {
                subject: workload.subject.clone(),
                client: workload.client.clone(),
                grants: BTreeMap::from([(workload.product, workload.grant.clone())]),
                casework_context: false,
            };
            let token = self
                .issuer
                .token(&self.input, &person, workload.product, expires_at)?;
            let state = self.token_document(name, generation, now, expires_at, &token);
            write_private(
                &self.root.join(token_file(name)),
                Zeroizing::new(serde_json::to_vec(&state)?).as_slice(),
            )?;
        }
        self.next_rotation = next_rotation(now, self.run_expires);
        Ok(())
    }

    fn connection_document(&self) -> Result<Value> {
        let bindings = self
            .input
            .plan
            .workloads
            .iter()
            .map(|(name, workload)| {
                let url = self
                    .urls
                    .get(&workload.product)
                    .context("workload product has no live URL")?;
                Ok(json!({
                    "name": name,
                    "product": workload.product,
                    "url": url,
                    "default": workload.default,
                    "credential": {
                        "type": "runner-token",
                        "tokenRef": format!("secret:file/{}", token_file(name)),
                        "runId": self.input.run_id,
                        "binding": name,
                        "issuer": self.input.plan.issuer,
                        "subject": workload.subject,
                        "clientId": workload.client,
                        "profile": workload.grant.profile,
                        "resource": self.input.plan.product(workload.product).audience,
                        "scopes": workload.grant.scopes,
                        "claims": workload.grant.claims,
                        "runExpiresAt": self.run_expires,
                    }
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(json!({
            "apiVersion": CONNECTION_FORMAT,
            "kind": CONNECTION_KIND,
            "service": format!("rstack-dev-{}", self.input.run_id),
            "audience": "service",
            "secretProviders": {"file": {"root": self.root}},
            "bindings": bindings,
        }))
    }

    fn token_document(
        &self,
        name: &str,
        generation: u64,
        issued_at: u64,
        expires_at: u64,
        token: &str,
    ) -> Value {
        let workload = &self.input.plan.workloads[name];
        json!({
            "apiVersion": TOKEN_FORMAT,
            "kind": TOKEN_KIND,
            "runId": self.input.run_id,
            "binding": name,
            "product": workload.product,
            "issuer": self.input.plan.issuer,
            "subject": workload.subject,
            "clientId": workload.client,
            "profile": workload.grant.profile,
            "resource": self.input.plan.product(workload.product).audience,
            "scopes": workload.grant.scopes,
            "claims": workload.grant.claims,
            "generation": generation,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "runExpiresAt": self.run_expires,
            "token": token,
        })
    }
}

fn token_file(name: &str) -> String {
    format!("workload-{name}.json")
}

fn next_rotation(now: u64, run_expires: u64) -> u64 {
    now.saturating_add(ROTATION_SECONDS).min(run_expires)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_dev::{plan::Plan, BregAuthority, RunInput};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde_json::json;
    use std::{collections::BTreeSet, os::unix::fs::PermissionsExt};

    #[test]
    fn rotation_schedule_never_extends_the_run() {
        assert_eq!(next_rotation(100, 1_000), 160);
        assert_eq!(next_rotation(980, 1_000), 1_000);
        assert_eq!(next_rotation(u64::MAX - 1, u64::MAX), u64::MAX);
    }

    #[test]
    fn token_file_names_are_binding_local_and_do_not_name_keys() {
        assert_eq!(token_file("registry"), "workload-registry.json");
        assert!(!token_file("registry").contains("key"));
    }

    #[test]
    fn one_private_atomic_file_replaces_a_complete_generation() {
        let scratch = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            scratch.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let path = scratch.path().join(token_file("registry"));
        let first = json!({"generation": 1, "token": "first"});
        let second = json!({"generation": 2, "token": "second"});
        write_private(&path, &serde_json::to_vec(&first).unwrap()).unwrap();
        write_private(&path, &serde_json::to_vec(&second).unwrap()).unwrap();
        let observed: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(observed, second);
    }

    #[test]
    fn prepared_connection_survives_two_generations_for_separate_product_authorities() {
        let scratch = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            scratch.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let run_id = "0123456789abcdef0123456789abcdef";
        let plan: Plan = serde_json::from_value(json!({
            "issuer": "https://issuer.example.invalid",
            "products": [
                {"product": "breg", "project": ".", "audience": "urn:test:breg"},
                {"product": "messaging", "project": ".", "audience": "urn:test:messaging"}
            ],
            "people": {"reader": {
                "subject": "reader", "client": "reader",
                "grants": {"breg": {"profile": "reader", "scopes": []}}
            }},
            "workloads": {"registry": {
                "product": "breg", "default": true,
                "subject": "service", "client": "service-client",
                "grant": {"profile": "service", "scopes": ["registry:read"]}
            }, "notices": {
                "product": "messaging", "default": true,
                "subject": "notice-service", "client": "notice-client",
                "grant": {
                    "profile": "service-sender", "scopes": ["messaging:send"],
                    "claims": {"registry_actor_kind": "service"}
                }
            }},
            "journey": {"id": "read", "steps": [{
                "id": "read", "product": "breg", "as": "reader", "method": "GET",
                "path": "/v1/records", "expect": {"status": 200}
            }]}
        }))
        .unwrap();
        let input = Arc::new(RunInput {
            run_id: run_id.to_owned(),
            project: scratch.path().to_owned(),
            plan,
            ttl_seconds: 600,
            schema_people: Vec::new(),
            breg_authority: Some(BregAuthority {
                principal: "registry_principal".to_owned(),
                purpose: false,
                requires_postgis: false,
                encrypts_fields: false,
                named_clients: BTreeSet::new(),
            }),
            casework_principals: BTreeMap::new(),
            messaging_clients: BTreeSet::new(),
            binaries: BTreeMap::new(),
        });
        let issuer = Arc::new(Issuer::create(scratch.path()).unwrap());
        let now = super::super::clock().unwrap();
        let run_expires = now + 600;
        let mut credentials = WorkloadCredentials::prepare(
            scratch.path(),
            input,
            issuer,
            &BTreeMap::from([
                (Product::Breg, "http://127.0.0.1:9999".to_owned()),
                (Product::Messaging, "http://127.0.0.1:9998".to_owned()),
            ]),
            now,
            run_expires,
        )
        .unwrap()
        .unwrap();

        let connection_bytes = std::fs::read(credentials.path()).unwrap();
        assert_eq!(
            std::fs::metadata(credentials.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let connection: Value = serde_json::from_slice(&connection_bytes).unwrap();
        assert_eq!(connection["kind"], CONNECTION_KIND);
        assert_eq!(
            connection["bindings"][0]["credential"]["type"],
            "runner-token"
        );
        assert_eq!(
            connection["bindings"][0]["credential"]["tokenRef"],
            "secret:file/workload-notices.json"
        );
        assert_eq!(connection["bindings"][0]["product"], "messaging");
        assert_eq!(
            connection["bindings"][0]["credential"]["resource"],
            "urn:test:messaging"
        );
        assert_eq!(
            connection["bindings"][0]["credential"]["claims"]["registry_actor_kind"],
            "service"
        );
        assert_eq!(connection["bindings"][1]["product"], "breg");
        let connection_text = String::from_utf8(connection_bytes).unwrap();
        assert!(!connection_text.contains("issuer-key"));
        assert!(!connection_text.contains("\"token\""));

        let token_path = scratch.path().join(DIRECTORY).join(token_file("registry"));
        let messaging_path = scratch.path().join(DIRECTORY).join(token_file("notices"));
        let first_messaging: Value =
            serde_json::from_slice(&std::fs::read(&messaging_path).unwrap()).unwrap();
        assert_eq!(first_messaging["kind"], TOKEN_KIND);
        assert_eq!(first_messaging["product"], "messaging");
        assert_eq!(first_messaging["resource"], "urn:test:messaging");
        assert_eq!(first_messaging["claims"]["registry_actor_kind"], "service");
        assert_ne!(first_messaging["token"], Value::Null);
        assert_eq!(
            std::fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let first: Value = serde_json::from_slice(&std::fs::read(&token_path).unwrap()).unwrap();
        assert_eq!(first["generation"], 1);
        assert_eq!(first["runExpiresAt"], run_expires);
        assert!(first["token"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        credentials.rotate_if_due(now + ROTATION_SECONDS).unwrap();
        let second: Value = serde_json::from_slice(&std::fs::read(token_path).unwrap()).unwrap();
        let second_messaging: Value =
            serde_json::from_slice(&std::fs::read(&messaging_path).unwrap()).unwrap();
        assert_eq!(second["generation"], 2);
        assert_eq!(second["runExpiresAt"], run_expires);
        assert_ne!(first["token"], second["token"]);
        assert_eq!(second_messaging["generation"], 2);
        assert_ne!(first_messaging["token"], second_messaging["token"]);
        assert!(second["expiresAt"].as_u64().unwrap() <= run_expires);
        for field in [
            "runId",
            "binding",
            "product",
            "issuer",
            "subject",
            "clientId",
            "profile",
            "resource",
            "scopes",
            "claims",
            "runExpiresAt",
        ] {
            assert_eq!(first[field], second[field], "{field}");
        }
        let claims = |state: &Value| {
            let encoded = state["token"].as_str().unwrap().split('.').nth(1).unwrap();
            serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap()
        };
        let first_claims = claims(&first);
        let second_claims = claims(&second);
        for field in [
            "iss",
            "aud",
            "sub",
            "client_id",
            "scope",
            "registry_principal",
        ] {
            assert_eq!(first_claims[field], second_claims[field], "{field}");
        }
        assert_eq!(second_claims["aud"], "urn:test:breg");
        assert_eq!(second_claims["sub"], "service");
        assert_eq!(second_claims["client_id"], "service-client");
        assert!(second_claims["exp"].as_u64().unwrap() <= run_expires);
        let messaging_claims = claims(&second_messaging);
        assert_eq!(messaging_claims["aud"], "urn:test:messaging");
        assert_eq!(messaging_claims["sub"], "notice-service");
        assert_eq!(messaging_claims["client_id"], "notice-client");
        assert_eq!(messaging_claims["scope"], "messaging:send");
        assert_eq!(messaging_claims["registry_actor_kind"], "service");

        credentials.invalidate(now + ROTATION_SECONDS + 1).unwrap();
        let stopped: Value = serde_json::from_slice(
            &std::fs::read(scratch.path().join(DIRECTORY).join(token_file("registry"))).unwrap(),
        )
        .unwrap();
        assert_eq!(stopped["status"], "stopped");
        assert_eq!(stopped["kind"], TOKEN_KIND);
        assert_eq!(stopped["generation"], 3);
        assert!(stopped.get("token").is_none());
        assert_eq!(stopped["expiresAt"], stopped["issuedAt"]);
        let messaging_stopped: Value =
            serde_json::from_slice(&std::fs::read(messaging_path).unwrap()).unwrap();
        assert_eq!(messaging_stopped["status"], "stopped");
        assert_eq!(messaging_stopped["generation"], 3);
        assert!(messaging_stopped.get("token").is_none());
    }
}
