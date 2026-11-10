// SPDX-License-Identifier: Apache-2.0
//! Activate ordinary packages and serve them on the run's private bindings.

use anyhow::{bail, ensure, Context, Result};
use registry_breg::fixtures::journey_step_profiles;
use rustix::process::{kill_process_group, waitid, Pid, Signal, WaitId, WaitIdOptions};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Seek},
    net::{Ipv4Addr, TcpListener},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use super::{
    bindings::{Bindings, RuntimeBindings},
    clock,
    database::{Database, DatabaseUrls},
    issuer::Issuer,
    plan::{self, Plan, Product},
    stopping, write_private, BregAuthority, RunInput, POLL,
};

pub(super) struct ProductRunner<'a> {
    input: Arc<RunInput>,
    root: &'a Path,
    terminate: &'a AtomicBool,
    deadline: Instant,
    runtime: tokio::runtime::Runtime,
    http: reqwest::Client,
    children: Vec<(Product, Child)>,
    bindings: Option<RuntimeBindings>,
}

impl<'a> ProductRunner<'a> {
    pub(super) fn new(
        input: Arc<RunInput>,
        root: &'a Path,
        terminate: &'a AtomicBool,
    ) -> Result<Self> {
        Ok(Self {
            input,
            root,
            terminate,
            deadline: Instant::now() + Duration::from_secs(300),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()?,
            children: Vec::new(),
            bindings: None,
        })
    }

    pub(super) fn check(&self) -> Result<()> {
        for entry in &self.input.plan.products {
            if entry.product == Product::Casework
                && self.input.plan.bindings.casework_context_provider.is_some()
            {
                // The owning tool validates the paired provider export before
                // packaging; the published source is left intact.
                continue;
            }
            self.tool(
                entry.product,
                "check",
                &[self.input.project.join(&entry.project).as_os_str()],
            )?;
        }
        Ok(())
    }

    pub(super) fn start(
        &mut self,
        database: &mut Database,
        issuer: Arc<Issuer>,
    ) -> Result<BTreeMap<Product, String>> {
        // Keep the reservations for later products until each is ready to bind.
        let ports: Vec<_> = self
            .input
            .plan
            .products
            .iter()
            .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
            .collect::<std::io::Result<_>>()
            .context("reserve loopback listeners")?;
        let urls = self
            .input
            .plan
            .products
            .iter()
            .zip(&ports)
            .map(|(entry, listener)| {
                Ok((entry.product, format!("http://{}", listener.local_addr()?)))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        self.bindings = Some(RuntimeBindings::prepare(
            self.root,
            self.input.clone(),
            issuer.clone(),
            &urls,
        )?);
        let mut breg_package = None;
        let input = self.input.clone();
        for (entry, reservation) in input.plan.products.iter().zip(ports) {
            self.ensure_active()?;
            let product = entry.product;
            let project = self.input.project.join(&entry.project);
            let url = &urls[&product];
            let bind = url.strip_prefix("http://").expect("local URL");
            let config = match product {
                Product::Breg => {
                    let (config, package) =
                        self.activate_breg(database, &issuer, &project, bind)?;
                    breg_package = Some(package);
                    config
                }
                Product::Casework => {
                    self.activate_casework(database, &project, bind, breg_package.as_deref())?
                }
            };
            let binaries = &self.input.binaries[&product];
            let mut command = child_command(&binaries.runtime);
            command.arg("--runtime-config").arg(config);
            if product == Product::Casework {
                command.arg("serve");
            }
            // Released runtimes own their listeners. If a competing process
            // takes this port in the handoff, startup fails and is cleaned up.
            drop(reservation);
            let child = command
                .stdout(Stdio::null())
                .spawn()
                .with_context(|| format!("cannot start {}", product.name()))?;
            self.children.push((product, child));
            self.ready(product, url)?;
        }
        Ok(urls)
    }

    fn activate_breg(
        &self,
        database: &mut Database,
        issuer: &Issuer,
        project: &Path,
        bind: &str,
    ) -> Result<(PathBuf, PathBuf)> {
        let requires_postgis = self
            .input
            .breg_authority
            .as_ref()
            .expect("BReg authority")
            .requires_postgis;
        let rehearsal = database.provision("breg_test", true, requires_postgis)?;
        let empty_package = self.root.join("breg-test-package");
        fs::create_dir(&empty_package)?;
        let config = self.config(
            Product::Breg,
            "breg-test",
            "127.0.0.1:0",
            &empty_package,
            rehearsal,
        )?;
        let credentials = self.schema_credentials(issuer)?;
        let receipt = self.root.join("schema-test-receipt.json");
        self.tool(
            Product::Breg,
            "test",
            &[
                project.as_os_str(),
                "--runtime-config".as_ref(),
                config.as_os_str(),
                "--credentials".as_ref(),
                credentials.as_os_str(),
                "--output".as_ref(),
                receipt.as_os_str(),
            ],
        )?;
        let build = self.root.join("breg-build");
        self.tool(
            Product::Breg,
            "package",
            &[
                project.as_os_str(),
                "--test-receipt".as_ref(),
                receipt.as_os_str(),
                "--output".as_ref(),
                build.as_os_str(),
            ],
        )?;
        let package = build.join("package");
        let urls = database.provision("breg", true, requires_postgis)?;
        let config = self.config(Product::Breg, "breg", bind, &package, urls)?;
        self.tool(
            Product::Breg,
            "apply",
            &[
                "--runtime-config".as_ref(),
                config.as_os_str(),
                "--package".as_ref(),
                package.as_os_str(),
                "--initial".as_ref(),
            ],
        )?;
        self.tool(
            Product::Breg,
            "verify",
            &["--runtime-config".as_ref(), config.as_os_str()],
        )?;
        Ok((config, package))
    }

    fn schema_credentials(&self, issuer: &Issuer) -> Result<PathBuf> {
        let mut bindings = Vec::with_capacity(self.input.schema_people.len());
        for (index, binding) in self.input.schema_people.iter().enumerate() {
            let token = issuer.token(
                &self.input,
                &self.input.plan.people[&binding.person],
                Product::Breg,
                clock()? + 300,
            )?;
            let filename = format!("breg-schema-token-{index}");
            write_private(&self.root.join(&filename), token.as_bytes())?;
            bindings.push(json!({
                "journeyId": binding.journey, "stepId": binding.step,
                "credential": {"type": "bearer", "tokenRef": format!("secret:file/{filename}")}
            }));
        }
        let path = self.root.join("schema-test-credentials.json");
        write_private(
            &path,
            &serde_json::to_vec(&json!({
                "apiVersion": crate::test_lifecycle::CREDENTIALS_API_VERSION,
                "kind": crate::test_lifecycle::CREDENTIALS_KIND,
                "bindings": bindings
            }))?,
        )?;
        Ok(path)
    }

    fn activate_casework(
        &self,
        database: &mut Database,
        project: &Path,
        bind: &str,
        breg_package: Option<&Path>,
    ) -> Result<PathBuf> {
        let paired;
        let project = if let Some(binding) = &self.input.plan.bindings.casework_context_provider {
            let source =
                breg_package.context("the Casework context provider needs the BReg package")?;
            paired = self.root.join("casework-paired");
            copy_project(project, &paired)?;
            self.tool(
                Product::Casework,
                "provider",
                &[
                    "pair".as_ref(),
                    paired.as_os_str(),
                    "--provider-id".as_ref(),
                    binding.id.as_ref(),
                    "--breg-package".as_ref(),
                    source.as_os_str(),
                    "--action-id".as_ref(),
                    binding.action.as_ref(),
                    "--bregctl-bin".as_ref(),
                    self.input.binaries[&Product::Breg].tool.as_os_str(),
                    "--apply".as_ref(),
                ],
            )?;
            self.tool(Product::Casework, "check", &[paired.as_os_str()])?;
            &paired
        } else {
            project
        };
        let package = self.root.join("casework-package");
        self.tool(
            Product::Casework,
            "package",
            &[
                project.as_os_str(),
                "--output".as_ref(),
                package.as_os_str(),
            ],
        )?;
        let urls = database.provision("casework", false, false)?;
        let config = self.config(Product::Casework, "casework", bind, &package, urls)?;
        let arguments = ["--runtime-config".as_ref(), config.as_os_str()];
        self.tool(Product::Casework, "apply", &arguments)?;
        self.tool(Product::Casework, "doctor", &arguments)?;
        Ok(config)
    }

    fn config(
        &self,
        product: Product,
        name: &str,
        bind: &str,
        package: &Path,
        urls: DatabaseUrls,
    ) -> Result<PathBuf> {
        let mut clients: BTreeSet<_> = self
            .input
            .plan
            .people
            .values()
            .filter(|person| person.grants.contains_key(&product))
            .map(|person| person.client.as_str())
            .collect();
        if product == Product::Breg {
            let authority = self.input.breg_authority.as_ref().expect("BReg authority");
            clients.extend(authority.named_clients.iter().map(String::as_str));
        }
        let mut oidc = json!({
            "issuer": self.input.plan.issuer,
            "audience": self.input.plan.product(product).audience,
            "allowedClients": clients,
            "scopeClaim": "scope",
            "jwksSource": {"type": "static", "documentRef": "secret:file/jwks"}
        });
        let mut database = json!({
            "runtimeUrlRef": self.secret(&format!("{name}-runtime-url"), urls.runtime.as_bytes())?,
            "migrationUrlRef": self.secret(&format!("{name}-migration-url"), urls.migration.as_bytes())?
        });
        if self.root.join("postgres-ca").is_file() {
            database["trustedRootCertificateRef"] = json!("secret:file/postgres-ca");
        }
        let audit = json!({
            "hashKeyRef": self.secret(&format!("{name}-audit-key"), random_secret()?.as_bytes())?,
            "path": self.root.join(format!("{name}-audit")).join("audit.jsonl"),
        });
        let identity = format!("dev-{}-{name}", self.input.run_id);
        let mut config = json!({
            "package": {"root": package},
            "secretProviders": {"file": {"root": self.root}},
            "database": database,
            "audit": audit,
        });
        match product {
            Product::Breg => {
                oidc["allowedAlgorithm"] = json!("ES256");
                oidc["accessTokenType"] = json!("at+jwt");
                oidc["scopeSeparator"] = json!(" ");
                oidc["maximumTokenLifetimeSeconds"] = json!(300);
                oidc["leewayMilliseconds"] = json!(1000);
                oidc["jwksCache"] = json!({
                    "cacheTtlSeconds": 600, "negativeCacheTtlSeconds": 60,
                    "refreshCooldownSeconds": 30, "maximumDocumentBytes": 65536,
                    "attemptTimeoutMilliseconds": 5000, "outageToleranceSeconds": 0
                });
                config["apiVersion"] = json!("id.registrystack.org/formats/breg/runtime/v1alpha1");
                config["kind"] = json!("BRegRuntimeConfig");
                config["database"]["pool"] = json!({"maximumConnections": 4});
                config["database"]["roles"] = json!({
                    "runtime": url::Url::parse(&urls.runtime)?.username(),
                    "migration": url::Url::parse(&urls.migration)?.username(),
                });
                config["audit"]["destination"] = json!("file");
                config["listener"] = json!({"bind": bind});
                let authority = self.input.breg_authority.as_ref().expect("BReg authority");
                if name == "breg" && authority.requires_postgis {
                    config["listener"]["publicOrigin"] = json!(format!("http://{bind}"));
                }
                config["identity"] = json!({
                    "environment": "development", "instanceId": identity,
                    "databaseId": identity, "databaseInitializationEnvironment": "development"
                });
                let mut authority_claims = json!({"principal": authority.principal});
                if authority.purpose {
                    authority_claims["purpose"] = json!("registry_purpose");
                }
                config["authentication"] = json!({
                    "oidc": oidc,
                    "authorityClaims": authority_claims
                });
                config["cursor"] = json!({
                    "secretRef": self.secret(&format!("{name}-cursor-key"), random_secret()?.as_bytes())?, "maximumAgeSeconds": 300
                });
                config["destinations"] = json!({"hooks": {}});
                config["operationalTimeouts"] = json!({
                    "httpRequestMilliseconds": 10000, "shutdownGraceMilliseconds": 1000,
                    "recordLockMilliseconds": 5000, "migrationLockMilliseconds": 30000,
                    "migrationStatementMilliseconds": 60000
                });
            }
            Product::Casework => {
                config["apiVersion"] =
                    json!("id.registrystack.org/formats/casework/runtime/v1alpha1");
                config["kind"] = json!("CaseworkRuntimeConfig");
                config["listener"] =
                    json!({"bind": bind, "tlsTermination": "development-loopback"});
                config["identity"] = json!({"databaseId": identity});
                config["authentication"] = json!({"oidc": oidc});
            }
        }
        if let Some(bindings) = &self.bindings {
            bindings.configure(product, &mut config);
        }
        let path = self.root.join(format!("{name}-runtime.yaml"));
        write_private(&path, &serde_json::to_vec(&config)?)?;
        Ok(path)
    }

    fn secret(&self, name: &str, bytes: &[u8]) -> Result<String> {
        write_private(&self.root.join(name), bytes)?;
        Ok(format!("secret:file/{name}"))
    }

    fn tool(&self, product: Product, stage: &str, args: &[&std::ffi::OsStr]) -> Result<()> {
        self.ensure_active()?;
        let mut output = tempfile::tempfile_in(self.root)?;
        let mut child = child_command(&self.input.binaries[&product].tool)
            .arg(stage)
            .args(args)
            .args(["--format", "json"])
            .stdout(output.try_clone()?)
            .spawn()
            .with_context(|| format!("cannot start {} {stage}", product.name()))?;
        if wait_for_tool(&mut child, || self.ensure_active())?.success() {
            return Ok(());
        }
        output.rewind()?;
        let codes = report_codes(output)?;
        bail!("{} {stage} failed{codes}", product.name());
    }

    fn ready(&mut self, product: Product, base: &str) -> Result<()> {
        let end = Instant::now() + Duration::from_secs(30);
        let url = format!("{base}/ready");
        loop {
            self.ensure_active()?;
            ensure!(
                self.services_alive()?,
                "{} exited before readiness",
                product.name()
            );
            if self
                .runtime
                .block_on(async { self.http.get(&url).send().await })
                .is_ok_and(|response| response.status().is_success())
            {
                ensure!(
                    self.services_alive()?,
                    "{} exited before readiness",
                    product.name()
                );
                return Ok(());
            }
            ensure!(
                Instant::now() < end,
                "{} did not become ready",
                product.name()
            );
            thread::sleep(POLL);
        }
    }

    pub(super) fn services_alive(&self) -> Result<bool> {
        for (_, child) in &self.children {
            if child_exited(child)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn ensure_active(&self) -> Result<()> {
        ensure!(
            !stopping(self.root, self.terminate),
            "development run was stopped"
        );
        ensure!(
            Instant::now() < self.deadline,
            "development run did not start within five minutes"
        );
        Ok(())
    }

    pub(super) fn stop(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        self.children.retain_mut(|(product, child)| {
            if stop_child(child).is_err() {
                failures.push(product.name());
                true
            } else {
                false
            }
        });
        ensure!(failures.is_empty(), "cannot stop {}", failures.join(", "));
        drop(self.bindings.take());
        Ok(())
    }

    pub(super) fn journey(
        &self,
        issuer: &Issuer,
        urls: &BTreeMap<Product, String>,
    ) -> Result<super::journey::JourneyReport> {
        super::journey::run(&self.input, issuer, urls, || self.ensure_active())
    }
}

fn random_secret() -> Result<zeroize::Zeroizing<String>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| anyhow::anyhow!("cannot generate a local key"))?;
    let mut encoded = zeroize::Zeroizing::new(String::new());
    URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut encoded);
    Ok(encoded)
}

fn copy_project(source: &Path, target: &Path) -> Result<()> {
    fn copy_dir(
        source: &Path,
        target: &Path,
        depth: usize,
        count: &mut usize,
        bytes: &mut u64,
    ) -> Result<()> {
        ensure!(
            depth <= 16,
            "Casework project directories exceed the depth limit"
        );
        fs::create_dir(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            if entry.file_name() == ".git" {
                continue;
            }
            *count += 1;
            ensure!(
                *count <= 256,
                "Casework project exceeds the file count limit"
            );
            let info = fs::symlink_metadata(entry.path())?;
            let destination = target.join(entry.file_name());
            if info.is_dir() {
                copy_dir(&entry.path(), &destination, depth + 1, count, bytes)?;
            } else {
                ensure!(
                    info.is_file(),
                    "Casework project contains a symlink or non-file entry"
                );
                *bytes = bytes.saturating_add(info.len());
                ensure!(
                    *bytes <= 32 * 1024 * 1024,
                    "Casework project exceeds the copy size limit"
                );
                fs::copy(entry.path(), destination)?;
            }
        }
        Ok(())
    }
    copy_dir(source, target, 0, &mut 0, &mut 0)
}

pub(super) fn breg_authority(root: &Path, plan: &Plan) -> Result<Option<BregAuthority>> {
    let Some(entry) = plan
        .products
        .iter()
        .find(|entry| entry.product == Product::Breg)
    else {
        return Ok(None);
    };
    let registry = crate::compile(
        &root.join(&entry.project),
        crate::ProfileArg::Production,
        "project-dev",
    )
    .map_err(|_| {
        anyhow::anyhow!(
            "BReg project check failed; run rstack breg check for the authored diagnostics"
        )
    })?;
    let review_authorities = registry
        .review_authorities()
        .iter()
        .map(|authority| authority.id.as_str())
        .collect();
    let actions = registry
        .actions()
        .actions
        .iter()
        .map(|action| action.id.as_str())
        .collect();
    validate_breg_binding_ids(&plan.bindings, &review_authorities, &actions)?;
    let profiles: BTreeSet<_> = registry
        .access_profile_displays()
        .iter()
        .map(|profile| profile.id.as_str())
        .collect();
    for (name, person) in &plan.people {
        if let Some(grant) = person.grants.get(&Product::Breg) {
            plan::require(
                profiles.contains(grant.profile.as_str()),
                &format!(
                    "/people/{}/grants/breg/profile",
                    registry_platform_yaml::escape_pointer_segment(name)
                ),
                "The BReg grant profile does not name an access profile in the BReg project.",
                "Set profile to an access profile defined by the BReg project.",
            )?;
        }
    }
    let inventory = registry_breg::authority::authority_inventory(&registry)?;
    ensure!(
        inventory.principal_claims.len() <= 1,
        "the BReg project's access profiles must select one principal claim"
    );
    let principal = inventory
        .principal_claims
        .into_iter()
        .next()
        .unwrap_or_else(|| "sub".to_owned());
    for (name, person) in &plan.people {
        if let Some(grant) = person.grants.get(&Product::Breg) {
            ensure!(!grant.claims.contains_key(&principal), "dev.yaml /people/{name}/grants/breg/claims cannot replace the BReg principal claim");
        }
    }
    Ok(Some(BregAuthority {
        principal,
        purpose: inventory.purpose_required,
        named_clients: crate::identity_facts::named_requester_clients(&registry),
        requires_postgis: breg_requires_postgis(&registry),
    }))
}

fn validate_breg_binding_ids(
    bindings: &Bindings,
    review_authorities: &BTreeSet<&str>,
    actions: &BTreeSet<&str>,
) -> plan::SemanticResult<()> {
    if let Some(binding) = &bindings.breg_review_authority {
        plan::require(
            review_authorities.contains(binding.id.as_str()),
            "/bindings/bregReviewAuthority/id",
            "The BReg review authority ID does not name a review authority in the BReg project.",
            "Set id to a review authority defined by the BReg project.",
        )?;
    }
    if let Some(binding) = &bindings.casework_context_provider {
        plan::require(
            actions.contains(binding.action.as_str()),
            "/bindings/caseworkContextProvider/action",
            "The Casework context provider action does not name an action in the BReg project.",
            "Set action to an action defined by the BReg project.",
        )?;
    }
    Ok(())
}

fn breg_requires_postgis(registry: &registry_breg::CompiledRegistry) -> bool {
    registry.ddl().requires_postgis
}

pub(super) fn casework_principals(
    root: &Path,
    plan: &Plan,
    breg: Option<&BregAuthority>,
    terminate: &AtomicBool,
) -> Result<BTreeMap<String, String>> {
    let Some(entry) = plan
        .products
        .iter()
        .find(|entry| entry.product == Product::Casework)
    else {
        return Ok(BTreeMap::new());
    };
    let tool = super::binaries(Product::Casework)?.tool;
    let facts = explain_casework_facts(&tool, &root.join(&entry.project), terminate)?;
    validate_casework_binding_ids(&plan.bindings, &facts)?;
    let mut principals = BTreeMap::new();
    for (name, person) in &plan.people {
        let Some(grant) = person.grants.get(&Product::Casework) else {
            continue;
        };
        let claim = facts.profiles.get(&grant.profile).map(String::as_str)
            .with_context(|| format!("dev.yaml /people/{name}/grants/casework/profile must name a Casework access profile"))?;
        ensure!(
            matches!(claim, "sub" | "registry_principal")
                || (!plan::reserved_claim(claim)
                    && !matches!(claim, "registry_actor_kind" | "registry_purpose")),
            "dev.yaml /people/{name}/grants/casework/profile names an incompatible principal claim"
        );
        ensure!(
            !grant.claims.contains_key(claim),
            "dev.yaml /people/{name}/grants/casework/claims cannot replace the Casework principal claim"
        );
        if person.casework_context {
            ensure!(
                claim == "sub" || breg.is_some_and(|authority| authority.principal == claim),
                "dev.yaml /people/{name}/caseworkContext requires Casework to read sub or the BReg principal claim"
            );
        }
        principals.insert(grant.profile.clone(), claim.to_owned());
    }
    Ok(principals)
}

fn explain_casework_facts(
    tool: &Path,
    project: &Path,
    terminate: &AtomicBool,
) -> Result<CaseworkFacts> {
    const MAX_REPORT: u64 = 4 * 1024 * 1024;

    let mut child = child_command(tool)
        .args(["--format", "json", "explain"])
        .arg(project)
        .stdout(Stdio::piped())
        .spawn()
        .context("cannot start caseworkctl explain")?;
    let stdout = child.stdout.take().expect("the explain output was piped");
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(MAX_REPORT + 1).read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = wait_for_tool(&mut child, || {
        ensure!(
            !terminate.load(Ordering::Relaxed),
            "development start was interrupted"
        );
        ensure!(Instant::now() < deadline, "caseworkctl explain timed out");
        Ok(())
    })?;
    let bytes = reader
        .join()
        .map_err(|_| anyhow::anyhow!("cannot collect the Casework authoring report"))??;
    ensure!(
        bytes.len() as u64 <= MAX_REPORT,
        "the Casework authoring report exceeds the size limit"
    );
    ensure!(
        status.success(),
        "Casework project check failed. Run rstack casework check for the authored diagnostics"
    );
    let report: Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("caseworkctl explain did not emit a JSON report"))?;
    casework_report_facts(&report)
}

#[derive(Debug, Eq, PartialEq)]
struct CaseworkFacts {
    profiles: BTreeMap<String, String>,
    trusted_producers: BTreeSet<String>,
    context_providers: BTreeSet<String>,
}

fn casework_report_facts(report: &Value) -> Result<CaseworkFacts> {
    ensure!(
        report["apiVersion"] == "id.registrystack.org/formats/casework/report/v1alpha2"
            && report["kind"] == "CaseworkReport"
            && report["command"] == "explain"
            && report["status"] == "complete"
            && report["ok"] == true,
        "caseworkctl explain returned an incompatible report"
    );
    // Each explained policy includes the whole project's access profiles.
    let profiles = report
        .pointer("/reviewPolicies/0/dependencies/accessProfiles")
        .and_then(Value::as_array)
        .context("caseworkctl explain did not report access profiles")?;
    let mut principals = BTreeMap::new();
    for profile in profiles {
        let id = profile["id"]
            .as_str()
            .context("an explained Casework profile has no ID")?;
        let claim = profile["principalClaim"]
            .as_str()
            .filter(|claim| !claim.is_empty())
            .context("an explained Casework profile has no principal claim")?;
        ensure!(
            principals.insert(id.to_owned(), claim.to_owned()).is_none(),
            "caseworkctl explain returned duplicate access profiles"
        );
    }
    Ok(CaseworkFacts {
        profiles: principals,
        trusted_producers: casework_report_ids(report, "trustedProducers")?,
        context_providers: casework_report_ids(report, "contextProviders")?,
    })
}

fn casework_report_ids(report: &Value, member: &str) -> Result<BTreeSet<String>> {
    let entries = report[member]
        .as_array()
        .with_context(|| format!("caseworkctl explain did not report {member}"))?;
    let mut ids = BTreeSet::new();
    for entry in entries {
        let id = entry["id"]
            .as_str()
            .with_context(|| format!("a caseworkctl explain {member} entry has no ID"))?;
        ensure!(
            ids.insert(id.to_owned()),
            "caseworkctl explain returned duplicate {member} IDs"
        );
    }
    Ok(ids)
}

fn validate_casework_binding_ids(
    bindings: &Bindings,
    facts: &CaseworkFacts,
) -> plan::SemanticResult<()> {
    if let Some(binding) = &bindings.breg_review_authority {
        plan::require(
            facts.trusted_producers.contains(&binding.producer),
            "/bindings/bregReviewAuthority/producer",
            "The BReg review producer does not name a trusted producer in the Casework project.",
            "Set producer to a trusted producer defined by the Casework project.",
        )?;
    }
    if let Some(binding) = &bindings.casework_context_provider {
        plan::require(
            facts.context_providers.contains(&binding.id),
            "/bindings/caseworkContextProvider/id",
            "The Casework context provider ID does not name a context provider in the Casework project.",
            "Set id to a context provider defined by the Casework project.",
        )?;
    }
    Ok(())
}

impl Drop for ProductRunner<'_> {
    fn drop(&mut self) {
        // The normal exit reports stop failures explicitly.
        for (_, child) in &mut self.children {
            let _ = stop_child(child);
        }
    }
}

pub(super) fn child_command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .env_remove("RSTACK_PROJECT_DEV_REQUEST")
        .process_group(0)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn child_pid(child: &Child) -> Result<Pid> {
    Pid::from_raw(i32::try_from(child.id())?).context("invalid owned process ID")
}

fn child_exited(child: &Child) -> Result<bool> {
    let pid = child_pid(child)?;
    // Keep the leader's PID until the group has received the final signal.
    // Reaping the leader first would allow reuse of the group ID.
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    loop {
        match waitid(WaitId::Pid(pid), options) {
            Ok(status) => return Ok(status.is_some()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn signal_group(child: &Child, signal: Signal) -> Result<()> {
    match kill_process_group(child_pid(child)?, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        // Darwin excludes zombies from killpg and reports EPERM when there
        // are no signalable members. An owned, same-user group with an
        // exited leader can already be empty of live processes.
        Err(rustix::io::Errno::PERM) if cfg!(target_os = "macos") && child_exited(child)? => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn stop_child(child: &mut Child) -> Result<ExitStatus> {
    if !child_exited(child)? {
        signal_group(child, Signal::TERM)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && !child_exited(child)? {
            thread::sleep(POLL);
        }
    }
    signal_group(child, Signal::KILL)?;
    Ok(child.wait()?)
}

fn wait_for_tool(child: &mut Child, active: impl Fn() -> Result<()>) -> Result<ExitStatus> {
    loop {
        if let Err(error) = active() {
            stop_child(child)?;
            return Err(error);
        }
        if child_exited(child)? {
            return stop_child(child);
        }
        thread::sleep(POLL);
    }
}

fn report_codes(output: impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    output.take(256 * 1024).read_to_end(&mut bytes)?;
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok(String::new());
    };
    let codes: BTreeSet<_> = value["diagnostics"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let code = item["code"].as_str().filter(|code| {
                code.len() <= 128
                    && code
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
            })?;
            let path = item["path"]
                .as_str()
                .or_else(|| item["pointer"].as_str())
                .filter(|path| {
                    !path.is_empty()
                        && path.len() <= 128
                        && path
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"-_./~".contains(&byte))
                });
            Some(path.map_or_else(|| code.to_owned(), |path| format!("{code} at {path}")))
        })
        .take(6)
        .collect();
    if codes.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!(
            " ({})",
            codes.into_iter().collect::<Vec<_>>().join(", ")
        ))
    }
}

#[derive(serde::Deserialize, Serialize)]
pub(super) struct SchemaPerson {
    journey: String,
    step: String,
    person: String,
}

fn breg_entry(plan: &Plan) -> Option<(usize, &plan::ProductPlan)> {
    plan.products
        .iter()
        .enumerate()
        .find(|(_, entry)| entry.product == Product::Breg)
}

fn schema_assignment_pointer(journey: &str, step: &str) -> String {
    format!(
        "/schemaTestPeople/{}/{}",
        registry_platform_yaml::escape_pointer_segment(journey),
        registry_platform_yaml::escape_pointer_segment(step)
    )
}

fn fixture_file_refusal<T>(plan: &Plan, field: &str) -> plan::SemanticResult<T> {
    if plan.schema_test_people.is_empty() {
        plan::refuse(
            field,
            "The BReg fixture journeys file must be a readable regular file inside the BReg product project.",
            "Place tests/journeys.yaml inside the BReg product project without linking it outside that project.",
        )
    } else {
        plan::refuse(
            "/schemaTestPeople",
            "The BReg fixture journeys file is missing, unreadable, or outside the BReg product project.",
            "Create a readable tests/journeys.yaml inside the BReg product project, or remove schemaTestPeople.",
        )
    }
}

pub(super) fn schema_people(
    root: &Path,
    plan: &Plan,
    required: bool,
) -> plan::SemanticResult<Vec<SchemaPerson>> {
    let Some((product_index, entry)) = breg_entry(plan) else {
        if !plan.schema_test_people.is_empty() {
            return plan::refuse(
                "/schemaTestPeople",
                "Schema test assignments require a BReg product.",
                "Add BReg to products, or remove schemaTestPeople.",
            );
        }
        return Ok(Vec::new());
    };
    let field = format!("/products/{product_index}/project");
    let product_root = match root.join(&entry.project).canonicalize() {
        Ok(path) if path.starts_with(root) && path.is_dir() => path,
        Ok(_) | Err(_) => return fixture_file_refusal(plan, &field),
    };
    let path = product_root.join("tests/journeys.yaml");
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && !required
                && plan.schema_test_people.is_empty() =>
        {
            return Ok(Vec::new());
        }
        Err(_) => return fixture_file_refusal(plan, &field),
    }
    let canonical = match path.canonicalize() {
        Ok(path) if path.starts_with(&product_root) && path.is_file() => path,
        Ok(_) | Err(_) => return fixture_file_refusal(plan, &field),
    };
    let bytes = match plan::read(
        &canonical,
        registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES as u64,
    ) {
        Ok(bytes) => bytes,
        Err(_) => {
            return plan::refuse(
                if plan.schema_test_people.is_empty() {
                    &field
                } else {
                    "/schemaTestPeople"
                },
                "The BReg fixture journeys file is unreadable or exceeds the 1 MiB limit.",
                "Make tests/journeys.yaml readable and no larger than 1 MiB, then run the check again.",
            );
        }
    };
    let steps = match journey_step_profiles(&bytes) {
        Ok(steps) => steps,
        Err(_) => {
            return plan::refuse(
                if plan.schema_test_people.is_empty() {
                    &field
                } else {
                    "/schemaTestPeople"
                },
                "The BReg fixture journeys file is not valid.",
                "Run `rstack breg check` for authored diagnostics, then correct tests/journeys.yaml.",
            );
        }
    };
    let mut fixture_steps = BTreeMap::<&str, BTreeSet<&str>>::new();
    for step in &steps {
        fixture_steps
            .entry(&step.journey_id)
            .or_default()
            .insert(&step.step_id);
    }
    for (journey, assignments) in &plan.schema_test_people {
        for step in assignments.keys() {
            let field = schema_assignment_pointer(journey, step);
            if !fixture_steps.contains_key(journey.as_str()) {
                return plan::refuse(
                    &field,
                    "The schema test assignment names a BReg fixture journey that does not exist.",
                    "Set the journey key to a journey defined in tests/journeys.yaml, or remove this assignment.",
                );
            }
            if !fixture_steps[journey.as_str()].contains(step.as_str()) {
                return plan::refuse(
                    &field,
                    "The schema test assignment names a BReg fixture step that does not exist in the named journey.",
                    "Set the step key to a step defined in that fixture journey, or remove this assignment.",
                );
            }
        }
    }
    let mut bindings = Vec::new();
    for step in steps {
        let eligible = |person: &plan::TestPerson| {
            person.grants.get(&Product::Breg).is_some_and(|grant| {
                grant.profile == step.access_profile
                    && step.scopes.as_ref().is_none_or(|scopes| {
                        scopes.iter().collect::<BTreeSet<_>>() == grant.scopes.iter().collect()
                    })
                    && step.purpose.as_ref().is_none_or(|purpose| {
                        grant.claims.get("registry_purpose").and_then(Value::as_str)
                            == Some(purpose)
                    })
            })
        };
        let explicit = plan
            .schema_test_people
            .get(&step.journey_id)
            .and_then(|steps| steps.get(&step.step_id));
        let aliases: Vec<_> = plan
            .people
            .iter()
            .filter(|(name, person)| {
                explicit.is_none_or(|selected| selected == *name) && eligible(person)
            })
            .map(|(name, _)| name)
            .collect();
        let [person] = aliases.as_slice() else {
            let field = schema_assignment_pointer(&step.journey_id, &step.step_id);
            return plan::refuse(
                &field,
                "A BReg fixture step must resolve to exactly one test person with matching profile, scopes, and purpose.",
                "Add or update a matching BReg grant, or select the matching person in schemaTestPeople.",
            );
        };
        bindings.push(SchemaPerson {
            journey: step.journey_id,
            step: step.step_id,
            person: (*person).clone(),
        });
    }
    Ok(bindings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_dev::bindings::{Bindings, BregReviewAuthority, CaseworkContextProvider};
    use std::{
        io::{BufRead, BufReader},
        sync::mpsc,
    };

    #[test]
    fn postgis_requirement_comes_from_the_compiled_breg_inventory() {
        let products = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/breg");
        for (project, expected) in [
            ("acceptance/spatial-service-sites", true),
            ("examples/minimal", false),
        ] {
            let compiled = crate::compile(
                &products.join(project),
                crate::ProfileArg::Production,
                "project-dev-test",
            )
            .unwrap_or_else(|_| panic!("{project} must compile"));
            assert_eq!(breg_requires_postgis(&compiled), expected, "{project}");
        }
    }

    #[test]
    fn the_casework_cli_report_owns_profile_principals() {
        let mut report = json!({
            "apiVersion": "id.registrystack.org/formats/casework/report/v1alpha2",
            "kind": "CaseworkReport", "command": "explain", "status": "complete", "ok": true,
            "reviewPolicies": [{"dependencies": {"accessProfiles": [
                {"id": "reviewer", "principalClaim": "sub", "requiredScopes": ["casework:staff"]},
                {"id": "producer", "principalClaim": "producer_identity"}
            ]}}],
            "trustedProducers": [],
            "contextProviders": []
        });
        assert_eq!(
            casework_report_facts(&report).unwrap().profiles,
            BTreeMap::from([
                ("producer".to_owned(), "producer_identity".to_owned()),
                ("reviewer".to_owned(), "sub".to_owned()),
            ])
        );
        let profiles = report
            .pointer_mut("/reviewPolicies/0/dependencies/accessProfiles")
            .unwrap()
            .as_array_mut()
            .unwrap();
        profiles.push(json!({"id": "reviewer", "principalClaim": "different"}));
        assert!(casework_report_facts(&report)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
        report["command"] = json!("check");
        assert!(casework_report_facts(&report)
            .unwrap_err()
            .to_string()
            .contains("incompatible report"));
    }

    fn product_bindings() -> Bindings {
        Bindings {
            breg_review_authority: Some(BregReviewAuthority {
                id: "review-authority".to_owned(),
                producer: "review-producer".to_owned(),
                identity: "reviewer".to_owned(),
            }),
            casework_context_provider: Some(CaseworkContextProvider {
                id: "proposal-context".to_owned(),
                identity: "context-reader".to_owned(),
                action: "review-action".to_owned(),
            }),
        }
    }

    #[test]
    fn breg_binding_ids_are_resolved_with_typed_value_free_refusals() {
        let bindings = product_bindings();
        let authorities = BTreeSet::from(["review-authority"]);
        let actions = BTreeSet::from(["review-action"]);
        validate_breg_binding_ids(&bindings, &authorities, &actions).unwrap();

        for (authorities, actions, field, reason, action) in [
            (
                BTreeSet::new(),
                actions.clone(),
                "/bindings/bregReviewAuthority/id",
                "The BReg review authority ID does not name a review authority in the BReg project.",
                "Set id to a review authority defined by the BReg project.",
            ),
            (
                authorities.clone(),
                BTreeSet::new(),
                "/bindings/caseworkContextProvider/action",
                "The Casework context provider action does not name an action in the BReg project.",
                "Set action to an action defined by the BReg project.",
            ),
        ] {
            let error = validate_breg_binding_ids(&bindings, &authorities, &actions)
                .unwrap_err()
                .to_string();
            assert!(error.contains(field), "{error}");
            assert!(error.contains(reason), "{error}");
            assert!(error.contains(action), "{error}");
            assert!(!error.contains("review-authority"), "{error}");
            assert!(!error.contains("review-action"), "{error}");
        }
    }

    #[test]
    fn casework_binding_ids_use_the_existing_explain_facts() {
        let bindings = product_bindings();
        let mut report = json!({
            "apiVersion": "id.registrystack.org/formats/casework/report/v1alpha2",
            "kind": "CaseworkReport", "command": "explain", "status": "complete", "ok": true,
            "reviewPolicies": [{"dependencies": {"accessProfiles": [
                {"id": "reviewer", "principalClaim": "sub"}
            ]}}],
            "trustedProducers": [{"id": "review-producer"}],
            "contextProviders": [{"id": "proposal-context"}]
        });
        let facts = casework_report_facts(&report).unwrap();
        validate_casework_binding_ids(&bindings, &facts).unwrap();

        for (member, field, reason, action) in [
            (
                "trustedProducers",
                "/bindings/bregReviewAuthority/producer",
                "The BReg review producer does not name a trusted producer in the Casework project.",
                "Set producer to a trusted producer defined by the Casework project.",
            ),
            (
                "contextProviders",
                "/bindings/caseworkContextProvider/id",
                "The Casework context provider ID does not name a context provider in the Casework project.",
                "Set id to a context provider defined by the Casework project.",
            ),
        ] {
            report[member] = json!([]);
            let facts = casework_report_facts(&report).unwrap();
            let error = validate_casework_binding_ids(&bindings, &facts)
                .unwrap_err()
                .to_string();
            assert!(error.contains(field), "{error}");
            assert!(error.contains(reason), "{error}");
            assert!(error.contains(action), "{error}");
            assert!(!error.contains("review-producer"), "{error}");
            assert!(!error.contains("proposal-context"), "{error}");
            report[member] = match member {
                "trustedProducers" => json!([{"id": "review-producer"}]),
                "contextProviders" => json!([{"id": "proposal-context"}]),
                _ => unreachable!(),
            };
        }
    }

    #[test]
    fn cancellation_closes_the_pipe_of_a_nested_tool() {
        closes_nested_tool_pipe(false);
    }

    #[test]
    fn cancellation_cleans_up_a_nested_tool_after_its_leader_exits() {
        closes_nested_tool_pipe(true);
    }

    #[test]
    fn completed_tool_without_descendants_keeps_its_exit_status() {
        let mut child = child_command(Path::new("/bin/sh"))
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap();
        wait_for_leader(&child);
        assert_eq!(stop_child(&mut child).unwrap().code(), Some(7));
    }

    fn wait_for_leader(child: &Child) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !child_exited(child).unwrap() {
            assert!(Instant::now() < deadline, "the tool leader did not exit");
            thread::sleep(POLL);
        }
    }

    fn closes_nested_tool_pipe(leader_exits: bool) {
        let leader_end = if leader_exits { "exit 0" } else { "wait" };
        let mut child = child_command(Path::new("/bin/sh"))
            .arg("-c")
            .arg(format!(
                "sh -c 'trap \"\" TERM; printf \"ready\\n\"; exec sleep 60' & {leader_end}"
            ))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child_pid(&child).unwrap();
        assert_eq!(rustix::process::getpgid(Some(pid)).unwrap(), pid);
        let mut pipe = BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        pipe.read_line(&mut ready).unwrap();
        assert_eq!(ready, "ready\n");
        if leader_exits {
            wait_for_leader(&child);
        }
        stop_child(&mut child).unwrap();

        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let _ = sender.send(pipe.read(&mut [0]));
        });
        let eof = receiver.recv_timeout(Duration::from_secs(3));
        if eof.is_err() {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        reader.join().unwrap();
        assert_eq!(eof.unwrap().unwrap(), 0);
    }
}
