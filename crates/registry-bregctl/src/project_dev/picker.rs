// SPDX-License-Identifier: Apache-2.0
//! Live-run descriptors and rotating person credentials for local Python pickers.

use anyhow::{ensure, Context, Result};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    issuer::{self, Issuer},
    plan::{DevelopmentPicker, PickerPersona, Product, TestPerson},
    private_directory, write_private, RunInput,
};

pub(super) const DESCRIPTOR_FORMAT: &str =
    "id.registrystack.org/formats/platform/dev-picker-descriptor/v1alpha1";
pub(super) const DESCRIPTOR_KIND: &str = "PlatformDevPickerDescriptor";
pub(super) const TOKEN_FORMAT: &str =
    "id.registrystack.org/formats/platform/dev-picker-token/v1alpha1";
pub(super) const TOKEN_KIND: &str = "PlatformDevPickerToken";
pub(super) const GENERATION_FORMAT: &str =
    "id.registrystack.org/formats/platform/dev-picker-generation/v1alpha1";
pub(super) const GENERATION_KIND: &str = "PlatformDevPickerGeneration";
const DIRECTORY: &str = "python-picker";
const DESCRIPTOR_FILE: &str = "picker.json";
const GENERATION_FILE: &str = "generation.json";
const ROTATION_SECONDS: u64 = 60;

struct PickerPerson {
    alias: String,
    selector: String,
    token_files: BTreeMap<Product, String>,
}

struct PickerState {
    persona: PickerPersona,
    root: PathBuf,
    origin: String,
    session_namespace: String,
    people: Vec<PickerPerson>,
}

/// One supervisor-owned credential set for every explicitly configured local
/// picker. The browser receives selectors and labels only; every credential
/// file remains in the owner-only run directory.
pub(super) struct PickerCredentials {
    input: Arc<RunInput>,
    issuer: Arc<Issuer>,
    urls: BTreeMap<Product, String>,
    workload_connection: Option<PathBuf>,
    pickers: Vec<PickerState>,
    generation: u64,
    next_rotation: u64,
    run_expires: u64,
}

impl PickerCredentials {
    pub(super) fn prepare(
        root: &Path,
        input: Arc<RunInput>,
        issuer: Arc<Issuer>,
        urls: &BTreeMap<Product, String>,
        workload_connection: Option<&Path>,
        now: u64,
        run_expires: u64,
    ) -> Result<Option<Self>> {
        if input.plan.development_pickers.is_empty() {
            return Ok(None);
        }
        ensure!(now < run_expires, "the development run has expired");
        let base = root.join(DIRECTORY);
        make_private_directory(&base).context("cannot create private Python picker state")?;
        let mut pickers = Vec::new();
        for (persona, plan) in input.plan.development_pickers.iter() {
            let picker_root = base.join(persona.name());
            make_private_directory(&picker_root)
                .context("cannot create private Python picker persona state")?;
            let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .context("cannot reserve a loopback Python picker origin")?;
            let origin = format!("http://{}", reservation.local_addr()?);
            drop(reservation);
            let people = plan
                .people
                .iter()
                .enumerate()
                .map(|(index, alias)| PickerPerson {
                    alias: alias.clone(),
                    selector: Uuid::new_v4().simple().to_string(),
                    token_files: plan
                        .person_products
                        .iter()
                        .map(|product| {
                            (
                                *product,
                                format!("credential-{index}-{}.json", product.name()),
                            )
                        })
                        .collect(),
                })
                .collect();
            pickers.push(PickerState {
                persona,
                root: picker_root,
                origin,
                session_namespace: Uuid::new_v4().simple().to_string(),
                people,
            });
        }
        let mut credentials = Self {
            input,
            issuer,
            urls: urls.clone(),
            workload_connection: workload_connection.map(Path::to_owned),
            pickers,
            generation: 0,
            next_rotation: now,
            run_expires,
        };
        credentials.rotate(now)?;
        for picker in &credentials.pickers {
            let descriptor = credentials.descriptor(picker, now)?;
            write_private(
                &picker.root.join(DESCRIPTOR_FILE),
                &serde_json::to_vec(&descriptor)?,
            )?;
        }
        Ok(Some(credentials))
    }

    pub(super) fn paths(&self) -> BTreeMap<&'static str, PathBuf> {
        self.pickers
            .iter()
            .map(|picker| (picker.persona.name(), picker.root.join(DESCRIPTOR_FILE)))
            .collect()
    }

    pub(super) fn rotate_if_due(&mut self, now: u64) -> Result<()> {
        if now >= self.next_rotation && now < self.run_expires {
            self.rotate(now)?;
        }
        Ok(())
    }

    pub(super) fn invalidate(&mut self, now: u64) -> Result<()> {
        let generation = self
            .generation
            .checked_add(1)
            .context("person token generation overflow")?;
        let stopped_at = now.min(self.run_expires);
        for picker in &self.pickers {
            for person in &picker.people {
                for (product, file) in &person.token_files {
                    let state = self.token_metadata(
                        picker, person, *product, generation, stopped_at, stopped_at,
                    );
                    let mut state = state.as_object().expect("token state object").clone();
                    state.insert("status".to_owned(), json!("stopped"));
                    write_private(
                        &picker.root.join(file),
                        &serde_json::to_vec(&Value::Object(state))?,
                    )?;
                }
            }
            self.write_generation(picker, generation, "stopped")?;
        }
        self.generation = generation;
        self.next_rotation = self.run_expires;
        Ok(())
    }

    fn rotate(&mut self, now: u64) -> Result<()> {
        let generation = self
            .generation
            .checked_add(1)
            .context("person token generation overflow")?;
        self.generation = generation;
        let expires_at = issuer::token_expiry(self.run_expires, now);
        ensure!(expires_at > now, "the development run has expired");
        for picker in &self.pickers {
            for person in &picker.people {
                let declared = &self.input.plan.people[&person.alias];
                for (product, file) in &person.token_files {
                    let grant = declared.grants[product].clone();
                    let mut claims = grant.claims.clone();
                    claims.insert(
                        "registry_dev_persona".to_owned(),
                        json!(picker.persona.name()),
                    );
                    let token_person = TestPerson {
                        subject: declared.subject.clone(),
                        client: declared.client.clone(),
                        grants: BTreeMap::from([(
                            *product,
                            super::plan::Grant { claims, ..grant },
                        )]),
                        casework_context: declared.casework_context,
                    };
                    let token = self.issuer.token_at(
                        &self.input,
                        &token_person,
                        *product,
                        now,
                        expires_at,
                    )?;
                    let mut state = self
                        .token_metadata(picker, person, *product, generation, now, expires_at)
                        .as_object()
                        .expect("token state object")
                        .clone();
                    state.insert("token".to_owned(), json!(&*token));
                    write_private(
                        &picker.root.join(file),
                        Zeroizing::new(serde_json::to_vec(&Value::Object(state))?).as_slice(),
                    )?;
                }
            }
            // Publishing the marker last makes a mixed file set unusable.
            self.write_generation(picker, generation, "ready")?;
        }
        self.next_rotation = now.saturating_add(ROTATION_SECONDS).min(self.run_expires);
        Ok(())
    }

    fn write_generation(&self, picker: &PickerState, generation: u64, status: &str) -> Result<()> {
        write_private(
            &picker.root.join(GENERATION_FILE),
            &serde_json::to_vec(&json!({
                "apiVersion": GENERATION_FORMAT,
                "kind": GENERATION_KIND,
                "status": status,
                "runId": self.input.run_id,
                "picker": picker.persona.name(),
                "generation": generation,
                "runExpiresAt": self.run_expires,
            }))?,
        )
    }

    fn descriptor(&self, picker: &PickerState, issued_at: u64) -> Result<Value> {
        let plan = picker_plan(&self.input, picker.persona);
        let product_set = plan
            .person_products
            .iter()
            .copied()
            .chain(
                plan.workloads
                    .iter()
                    .map(|name| self.input.plan.workloads[name].product),
            )
            .collect::<BTreeSet<_>>();
        let products = product_set
            .iter()
            .map(|product| {
                (
                    product.name().to_owned(),
                    json!({
                        "url": self.urls[product],
                        "resource": self.input.plan.product(*product).audience,
                    }),
                )
            })
            .collect::<Map<_, _>>();
        let people = picker
            .people
            .iter()
            .map(|person| {
                let declared = &self.input.plan.people[&person.alias];
                let credentials = person
                    .token_files
                    .iter()
                    .map(|(product, token_ref)| {
                        let grant = &declared.grants[product];
                        (
                            product.name().to_owned(),
                            json!({
                                "tokenFile": token_ref,
                                "profile": grant.profile,
                                "resource": self.input.plan.product(*product).audience,
                                "audiences": audiences(&self.input, declared, *product),
                                "scopes": grant.scopes,
                                "principalClaim": principal_claim(&self.input, grant, *product),
                            }),
                        )
                    })
                    .collect::<Map<_, _>>();
                json!({
                    "selector": person.selector,
                    "label": person.alias,
                    "subject": declared.subject,
                    "principal": declared.subject,
                    "clientId": declared.client,
                    "credentials": credentials,
                })
            })
            .collect::<Vec<_>>();
        let workloads = plan
            .workloads
            .iter()
            .map(|name| {
                let workload = &self.input.plan.workloads[name];
                json!({
                    "name": name,
                    "product": workload.product,
                    "default": workload.default,
                    "url": self.urls[&workload.product],
                    "issuer": self.input.plan.issuer,
                    "subject": workload.subject,
                    "clientId": workload.client,
                    "profile": workload.grant.profile,
                    "resource": self.input.plan.product(workload.product).audience,
                    "scopes": workload.grant.scopes,
                    "claims": workload.grant.claims,
                })
            })
            .collect::<Vec<_>>();
        if !plan.workloads.is_empty() {
            ensure!(
                self.workload_connection.is_some(),
                "development picker workloads need the run's generated connection"
            );
        }
        let mut descriptor = json!({
            "apiVersion": DESCRIPTOR_FORMAT,
            "kind": DESCRIPTOR_KIND,
            "runId": self.input.run_id,
            "persona": picker.persona.name(),
            "origin": picker.origin,
            "sessionNamespace": picker.session_namespace,
            "issuedAt": issued_at,
            "expiresAt": self.run_expires,
            "generationFile": GENERATION_FILE,
            "products": products,
            "people": people,
            "workloads": workloads,
        });
        if !plan.workloads.is_empty() {
            descriptor["workloadConnectionFile"] =
                json!("../../python-workload/python-connection.json");
        }
        Ok(descriptor)
    }

    fn token_metadata(
        &self,
        picker: &PickerState,
        person: &PickerPerson,
        product: Product,
        generation: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Value {
        let declared = &self.input.plan.people[&person.alias];
        let grant = &declared.grants[&product];
        json!({
            "apiVersion": TOKEN_FORMAT,
            "kind": TOKEN_KIND,
            "runId": self.input.run_id,
            "picker": picker.persona.name(),
            "persona": picker.persona.name(),
            "selector": person.selector,
            "product": product,
            "issuer": self.input.plan.issuer,
            "subject": declared.subject,
            "principal": declared.subject,
            "clientId": declared.client,
            "profile": grant.profile,
            "resource": self.input.plan.product(product).audience,
            "audiences": audiences(&self.input, declared, product),
            "scopes": grant.scopes,
            "principalClaim": principal_claim(&self.input, grant, product),
            "generation": generation,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
            "runExpiresAt": self.run_expires,
        })
    }
}

fn picker_plan(input: &RunInput, persona: PickerPersona) -> &DevelopmentPicker {
    match persona {
        PickerPersona::Holder => input.plan.development_pickers.holder.as_ref(),
        PickerPersona::Staff => input.plan.development_pickers.staff.as_ref(),
    }
    .expect("configured picker")
}

fn audiences<'a>(input: &'a RunInput, person: &TestPerson, product: Product) -> Vec<&'a str> {
    if product == Product::Casework && person.casework_context {
        vec![
            &input.plan.product(Product::Casework).audience,
            &input.plan.product(Product::Breg).audience,
        ]
    } else {
        vec![&input.plan.product(product).audience]
    }
}

fn principal_claim<'a>(
    input: &'a RunInput,
    grant: &'a super::plan::Grant,
    product: Product,
) -> &'a str {
    match product {
        Product::Breg => {
            &input
                .breg_authority
                .as_ref()
                .expect("BReg authority")
                .principal
        }
        Product::Casework => &input.casework_principals[&grant.profile],
        Product::Messaging => "sub",
    }
}

fn make_private_directory(path: &Path) -> Result<()> {
    match private_directory(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            super::ensure_private(path, false)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_dev::{plan::Plan, BregAuthority, RunInput};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use std::{collections::BTreeSet, os::unix::fs::PermissionsExt};

    fn input(root: &Path) -> Arc<RunInput> {
        let plan: Plan = serde_json::from_value(json!({
            "issuer": "https://issuer.example.test",
            "products": [
                {"product": "breg", "project": ".", "audience": "urn:test:breg"},
                {"product": "casework", "project": ".", "audience": "urn:test:casework"},
                {"product": "messaging", "project": ".", "audience": "urn:test:messaging"}
            ],
            "people": {"applicant": {
                "subject": "person-one", "client": "portal-client",
                "grants": {
                    "breg": {"profile": "applicant", "scopes": ["breg:read"]},
                    "casework": {"profile": "requester", "scopes": ["casework:read"]}
                }
            }},
            "workloads": {"notices": {
                "product": "messaging", "default": true,
                "subject": "notice-service", "client": "notice-client",
                "grant": {"profile": "service-sender", "scopes": ["messaging:send"]}
            }},
            "developmentPickers": {"holder": {
                "people": ["applicant"],
                "personProducts": ["breg", "casework"],
                "workloads": ["notices"]
            }},
            "journey": {"id": "read", "steps": [{
                "id": "read", "product": "breg", "as": "applicant", "method": "GET",
                "path": "/v1/records", "expect": {"status": 200}
            }]}
        }))
        .unwrap();
        Arc::new(RunInput {
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
            project: root.to_owned(),
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
            casework_principals: BTreeMap::from([(
                "requester".to_owned(),
                "registry_principal".to_owned(),
            )]),
            messaging_clients: BTreeSet::new(),
            binaries: BTreeMap::new(),
        })
    }

    #[test]
    fn descriptor_omits_workload_reference_when_no_workloads_exist() {
        let scratch = tempfile::tempdir().unwrap();
        std::fs::set_permissions(scratch.path(), PermissionsExt::from_mode(0o700)).unwrap();
        let mut input = input(scratch.path());
        let plan = &mut Arc::get_mut(&mut input).unwrap().plan;
        plan.workloads.clear();
        plan.development_pickers
            .holder
            .as_mut()
            .unwrap()
            .workloads
            .clear();
        let issuer = Arc::new(Issuer::create(scratch.path()).unwrap());
        let now = super::super::clock().unwrap();
        let credentials = PickerCredentials::prepare(
            scratch.path(),
            input,
            issuer,
            &BTreeMap::from([
                (Product::Breg, "http://127.0.0.1:41001".to_owned()),
                (Product::Casework, "http://127.0.0.1:41002".to_owned()),
            ]),
            None,
            now,
            now + 600,
        )
        .unwrap()
        .unwrap();
        let descriptor: Value =
            serde_json::from_slice(&std::fs::read(&credentials.paths()["holder"]).unwrap())
                .unwrap();
        assert!(descriptor.get("workloadConnectionFile").is_none());
    }

    #[test]
    fn descriptor_and_tokens_are_bounded_to_one_live_run_and_rotate_as_a_set() {
        let scratch = tempfile::tempdir().unwrap();
        std::fs::set_permissions(scratch.path(), PermissionsExt::from_mode(0o700)).unwrap();
        let workload = scratch.path().join("python-workload");
        make_private_directory(&workload).unwrap();
        let connection = workload.join("python-connection.json");
        write_private(&connection, b"{}").unwrap();
        let input = input(scratch.path());
        let issuer = Arc::new(Issuer::create(scratch.path()).unwrap());
        let now = super::super::clock().unwrap();
        let run_expires = now + 600;
        let mut credentials = PickerCredentials::prepare(
            scratch.path(),
            input,
            issuer,
            &BTreeMap::from([
                (Product::Breg, "http://127.0.0.1:41001".to_owned()),
                (Product::Casework, "http://127.0.0.1:41002".to_owned()),
                (Product::Messaging, "http://127.0.0.1:41003".to_owned()),
            ]),
            Some(&connection),
            now,
            run_expires,
        )
        .unwrap()
        .unwrap();

        let descriptor_path = credentials.paths()["holder"].clone();
        let descriptor_bytes = std::fs::read(&descriptor_path).unwrap();
        let descriptor: Value = serde_json::from_slice(&descriptor_bytes).unwrap();
        assert_eq!(descriptor["kind"], DESCRIPTOR_KIND);
        assert_eq!(descriptor["persona"], "holder");
        assert!(descriptor["origin"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:"));
        assert_eq!(descriptor["people"][0]["label"], "applicant");
        assert_ne!(descriptor["people"][0]["selector"], "applicant");
        assert_eq!(
            descriptor["people"][0]["credentials"]["breg"]["tokenFile"],
            "credential-0-breg.json"
        );
        assert_eq!(descriptor["workloads"][0]["name"], "notices");
        assert_eq!(
            descriptor["workloadConnectionFile"],
            "../../python-workload/python-connection.json"
        );
        let descriptor_text = String::from_utf8(descriptor_bytes).unwrap();
        assert!(!descriptor_text.contains("issuer-key"));
        assert!(!descriptor_text.contains("\"token\""));
        assert_eq!(
            std::fs::metadata(&descriptor_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let picker_root = descriptor_path.parent().unwrap();
        let breg_path = picker_root.join("credential-0-breg.json");
        let first: Value = serde_json::from_slice(&std::fs::read(&breg_path).unwrap()).unwrap();
        assert_eq!(first["generation"], 1);
        assert_eq!(first["persona"], "holder");
        let payload = first["token"].as_str().unwrap().split('.').nth(1).unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert_eq!(claims["registry_dev_persona"], "holder");
        assert_eq!(claims["aud"], "urn:test:breg");
        assert_eq!(claims["iat"], first["issuedAt"]);
        assert_eq!(claims["exp"], first["expiresAt"]);

        credentials.rotate_if_due(now + ROTATION_SECONDS).unwrap();
        let second: Value = serde_json::from_slice(&std::fs::read(&breg_path).unwrap()).unwrap();
        let marker: Value =
            serde_json::from_slice(&std::fs::read(picker_root.join(GENERATION_FILE)).unwrap())
                .unwrap();
        assert_eq!(second["generation"], 2);
        assert_eq!(marker["generation"], 2);
        assert_ne!(first["token"], second["token"]);
        for field in [
            "runId",
            "picker",
            "persona",
            "selector",
            "product",
            "issuer",
            "subject",
            "principal",
            "clientId",
            "profile",
            "resource",
            "audiences",
            "scopes",
            "principalClaim",
            "runExpiresAt",
        ] {
            assert_eq!(first[field], second[field], "{field}");
        }

        credentials.invalidate(now + ROTATION_SECONDS + 1).unwrap();
        let stopped_marker: Value =
            serde_json::from_slice(&std::fs::read(picker_root.join(GENERATION_FILE)).unwrap())
                .unwrap();
        let stopped: Value = serde_json::from_slice(&std::fs::read(&breg_path).unwrap()).unwrap();
        assert_eq!(stopped_marker["status"], "stopped");
        assert_eq!(stopped_marker["generation"], 3);
        assert_eq!(stopped["status"], "stopped");
        assert!(stopped.get("token").is_none());
    }
}
