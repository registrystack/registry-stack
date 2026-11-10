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
    io::{Read, Seek, SeekFrom},
    net::{Ipv4Addr, TcpListener},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
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
    private_directory, stopping, write_private, BregAuthority, RunInput, POLL,
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
            let log = open_log(self.root, &format!("{}-runtime", product.name()))?;
            command.stdout(log.try_clone()?).stderr(log);
            // Released runtimes own their listeners, so the reservation is
            // released before the spawn. A competing process can take the port
            // in that gap; the runtime then fails to bind and exits, which the
            // readiness wait reports along with the end of its log.
            drop(reservation);
            let child = command
                .spawn()
                .with_context(|| format!("cannot start {}", product.name()))?;
            self.children.push((product, child));
            self.record_processes()?;
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
        let mut arguments = vec![std::ffi::OsStr::new(stage)];
        arguments.extend_from_slice(args);
        arguments.extend(["--format", "json"].map(std::ffi::OsStr::new));
        run_logged_tool(
            &self.input.binaries[&product].tool,
            &arguments,
            self.root,
            (product.name(), stage),
            || self.ensure_active(),
        )
    }

    /// Record every live child's process group so a later `stop` can reach
    /// processes whose supervisor died.
    fn record_processes(&self) -> Result<()> {
        let entries: Vec<_> = self
            .children
            .iter()
            .map(|(product, child)| (*product, child.id()))
            .collect();
        write_processes(self.root, &entries)
    }

    fn ready(&mut self, product: Product, base: &str) -> Result<()> {
        let end = Instant::now() + Duration::from_secs(30);
        let url = format!("{base}/ready");
        loop {
            self.ensure_active()?;
            self.ensure_alive(product)?;
            if self
                .runtime
                .block_on(async { self.http.get(&url).send().await })
                .is_ok_and(|response| response.status().is_success())
            {
                self.ensure_alive(product)?;
                return Ok(());
            }
            ensure!(
                Instant::now() < end,
                "{} did not become ready{}",
                product.name(),
                self.runtime_log_tail(product)
            );
            thread::sleep(POLL);
        }
    }

    /// Fail while waiting on `waiting`, naming whichever child exited.
    fn ensure_alive(&self, waiting: Product) -> Result<()> {
        for (product, child) in &self.children {
            if child_exited(child)? {
                let detail = self.runtime_log_tail(*product);
                if *product == waiting {
                    bail!("{} exited before readiness{detail}", product.name());
                }
                bail!(
                    "{} exited while {} was starting{detail}",
                    product.name(),
                    waiting.name()
                );
            }
        }
        Ok(())
    }

    fn runtime_log_tail(&self, product: Product) -> String {
        failure_detail(&log_path(self.root, &format!("{}-runtime", product.name())))
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
        // Drop reaped groups from the record so a later recovery cannot signal
        // a reused process group ID.
        self.record_processes()?;
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

fn log_path(root: &Path, name: &str) -> PathBuf {
    root.join("logs").join(format!("{name}.log"))
}

/// Open the owner-only log for one product stage, appending to earlier output.
fn open_log(root: &Path, name: &str) -> Result<fs::File> {
    let directory = root.join("logs");
    match private_directory(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("cannot create the development log directory"),
    }
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log_path(root, name))
        .with_context(|| format!("cannot open the {name} log"))
}

const LOG_TAIL_LINES: usize = 20;
const LOG_TAIL_BYTES: u64 = 4096;

/// The last lines of a log, at most 4 KiB, decoded lossily. An unreadable
/// log yields an empty tail; the caller reports the path either way.
fn log_tail(path: &Path) -> String {
    let Ok(mut file) = fs::File::open(path) else {
        return String::new();
    };
    let mut bytes = Vec::new();
    let read = file
        .metadata()
        .map(|meta| meta.len())
        .and_then(|length| file.seek(SeekFrom::Start(length.saturating_sub(LOG_TAIL_BYTES))))
        .and_then(|_| file.take(LOG_TAIL_BYTES).read_to_end(&mut bytes));
    if read.is_err() {
        return String::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<_> = text.lines().collect();
    lines[lines.len().saturating_sub(LOG_TAIL_LINES)..]
        .join("\n")
        .trim()
        .to_owned()
}

/// The suffix appended to a stage failure: the log path and its last lines.
fn failure_detail(path: &Path) -> String {
    let tail = log_tail(path);
    if tail.is_empty() {
        format!(" (log: {})", path.display())
    } else {
        format!(" (log: {}); last lines:\n{tail}", path.display())
    }
}

/// Run a product tool with its stderr in `<root>/logs/<name>.log`. Stdout is
/// the JSON report, which supplies the diagnostic codes of a failure.
fn run_logged_tool(
    binary: &Path,
    args: &[&std::ffi::OsStr],
    root: &Path,
    (product, stage): (&str, &str),
    active: impl Fn() -> Result<()>,
) -> Result<()> {
    let name = format!("{product}-{stage}");
    let mut output = tempfile::tempfile_in(root)?;
    let mut child = child_command(binary)
        .args(args)
        .stdout(output.try_clone()?)
        .stderr(open_log(root, &name)?)
        .spawn()
        .with_context(|| format!("cannot start {product} {stage}"))?;
    if wait_for_tool(&mut child, active)?.success() {
        return Ok(());
    }
    output.rewind()?;
    let codes = report_codes(output)?;
    bail!(
        "{product} {stage} failed{codes}{}",
        failure_detail(&log_path(root, &name))
    );
}

/// Record each child's process group. Children start as group leaders, so the
/// group ID is the PID.
fn write_processes(root: &Path, children: &[(Product, u32)]) -> Result<()> {
    let entries: Vec<_> = children
        .iter()
        .map(|(product, pid)| json!({"product": product.name(), "pid": pid, "pgid": pid}))
        .collect();
    write_private(&root.join("processes.json"), &serde_json::to_vec(&entries)?)
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

pub(super) struct ProductInspection {
    pub(super) breg_authority: Option<BregAuthority>,
    pub(super) casework_principals: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
#[error("{reason}")]
pub(super) struct InspectionUnavailable {
    field: String,
    reason: String,
    remedy: String,
}

impl InspectionUnavailable {
    fn new(field: &str, reason: &str, remedy: &str) -> Self {
        Self {
            field: field.to_owned(),
            reason: reason.to_owned(),
            remedy: remedy.to_owned(),
        }
    }

    pub(super) fn field(&self) -> &str {
        &self.field
    }

    pub(super) fn reason(&self) -> &str {
        &self.reason
    }

    pub(super) fn remedy(&self) -> &str {
        &self.remedy
    }
}

struct SelectedProduct {
    field: String,
    root: PathBuf,
}

pub(super) fn inspect(
    root: &Path,
    plan: &Plan,
    terminate: &AtomicBool,
) -> Result<ProductInspection> {
    let breg_authority = breg_authority(root, plan)?;
    let casework_principals = casework_principals(root, plan, breg_authority.as_ref(), terminate)?;
    Ok(ProductInspection {
        breg_authority,
        casework_principals,
    })
}

fn product_root(
    root: &Path,
    plan: &Plan,
    product: Product,
) -> plan::SemanticResult<Option<SelectedProduct>> {
    let Some((index, entry)) = plan
        .products
        .iter()
        .enumerate()
        .find(|(_, entry)| entry.product == product)
    else {
        return Ok(None);
    };
    let field = format!("/products/{index}/project");
    let project = root.join(&entry.project).canonicalize().map_err(|_| {
        plan::SemanticRefusal::new(
            &field,
            "The selected product project directory cannot be resolved.",
            "Restore the product project directory inside the development project.",
        )
    })?;
    plan::require(
        project.starts_with(root) && project.is_dir(),
        &field,
        "The selected product project directory is outside the development project.",
        "Select a product project directory inside the development project.",
    )?;
    let manifest_name = match product {
        Product::Breg => "registry.yaml",
        Product::Casework => "casework.yaml",
    };
    let manifest = project.join(manifest_name).canonicalize().map_err(|_| {
        plan::SemanticRefusal::new(
            &field,
            "The selected product manifest cannot be resolved.",
            format!("Restore {manifest_name} inside the selected product project."),
        )
    })?;
    plan::require(
        manifest.starts_with(&project) && manifest.is_file(),
        &field,
        "The selected product manifest is outside the selected product project.",
        format!("Place {manifest_name} inside the selected product project."),
    )?;
    Ok(Some(SelectedProduct {
        field,
        root: project,
    }))
}

fn breg_authority(root: &Path, plan: &Plan) -> Result<Option<BregAuthority>> {
    let Some(project) = product_root(root, plan, Product::Breg)? else {
        return Ok(None);
    };
    let registry = crate::compile(&project.root, crate::ProfileArg::Production, "project-dev")
        .map_err(|_| {
            plan::SemanticRefusal::new(
                &project.field,
                "The BReg project did not pass its owning validation.",
                "Run `rstack breg check` for authored diagnostics, then correct the BReg project.",
            )
        })?;
    refuse_encrypted_fields(&registry)?;
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
    check_breg_grants(&registry, &plan.people)?;
    let inventory = registry_breg::authority::authority_inventory(&registry)?;
    let principal = breg_principal(plan, &project.field, &inventory.principal_claims)?;
    Ok(Some(BregAuthority {
        principal,
        purpose: inventory.purpose_required,
        named_clients: crate::identity_facts::named_requester_clients(&registry),
        requires_postgis: breg_requires_postgis(&registry),
    }))
}

fn breg_principal(
    plan: &Plan,
    product_field: &str,
    principal_claims: &BTreeSet<String>,
) -> plan::SemanticResult<String> {
    plan::require(
        principal_claims.len() <= 1,
        product_field,
        "The BReg access profiles select more than one principal claim.",
        "Use one principal claim across the BReg project's access profiles.",
    )?;
    let principal = principal_claims
        .iter()
        .next()
        .cloned()
        .unwrap_or_else(|| "sub".to_owned());
    for (name, person) in &plan.people {
        if let Some(grant) = person.grants.get(&Product::Breg) {
            plan::require(
                !grant.claims.contains_key(&principal),
                &format!(
                    "/people/{}/grants/breg/claims",
                    registry_platform_yaml::escape_pointer_segment(name)
                ),
                "The BReg grant claims cannot replace the principal claim selected by the BReg project.",
                "Remove the selected principal claim from this grant's additional claims.",
            )?;
        }
    }
    Ok(principal)
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

/// The generated runtime configuration has no field-encryption provider, so a
/// project with encrypted fields would only fail late and obscurely.
fn refuse_encrypted_fields(registry: &registry_breg::CompiledRegistry) -> Result<()> {
    for entity in registry.entities().values() {
        for field in entity.fields.values() {
            ensure!(
                field.encryption.is_none(),
                "rstack dev does not configure field encryption yet; {}.{} is encrypted",
                entity.id,
                field.id
            );
        }
    }
    Ok(())
}

/// Every BReg grant must name an access profile the project declares,
/// including profiles that carry only proposal permissions and so belong to no
/// entity. Scopes are not checked here: a profile's required scopes are a
/// per-entity rule the runtime applies, and a mismatch surfaces when the
/// journey runs.
fn check_breg_grants(
    registry: &registry_breg::CompiledRegistry,
    people: &BTreeMap<String, plan::TestPerson>,
) -> plan::SemanticResult<()> {
    let profiles: BTreeSet<_> = registry
        .access_profile_displays()
        .iter()
        .map(|profile| profile.id.as_str())
        .collect();
    for (name, person) in people {
        if let Some(grant) = person.grants.get(&Product::Breg) {
            plan::require(
                profiles.contains(grant.profile.as_str()),
                &format!(
                    "/people/{}/grants/breg/profile",
                    registry_platform_yaml::escape_pointer_segment(name)
                ),
                "The BReg grant profile does not name an access profile in the BReg project.",
                format!(
                    "Set profile to an access profile defined by the BReg project. It declares: {}.",
                    profiles.iter().copied().collect::<Vec<_>>().join(", ")
                ),
            )?;
        }
    }
    Ok(())
}

fn breg_requires_postgis(registry: &registry_breg::CompiledRegistry) -> bool {
    registry.ddl().requires_postgis
}

fn casework_principals(
    root: &Path,
    plan: &Plan,
    breg: Option<&BregAuthority>,
    terminate: &AtomicBool,
) -> Result<BTreeMap<String, String>> {
    let Some(project) = product_root(root, plan, Product::Casework)? else {
        return Ok(BTreeMap::new());
    };
    let tool = super::product_tool(Product::Casework).map_err(|_| {
        InspectionUnavailable::new(
            &project.field,
            "The Casework project cannot be inspected because its owning tool is unavailable.",
            "Install the matching Casework tools or provide RSTACK_CASEWORKCTL_BIN, then run the check again.",
        )
    })?;
    let facts = match explain_casework_facts(&tool, &project.root, terminate) {
        Ok(facts) => facts,
        Err(error) if error.is::<InvalidCaseworkProject>() => {
            return Err(plan::SemanticRefusal::new(
                &project.field,
                "The Casework project did not pass validation by its owning tool.",
                "Run `rstack casework check` for authored diagnostics, then correct the Casework project.",
            ).into());
        }
        Err(_) => {
            return Err(InspectionUnavailable::new(
                &project.field,
                "The selected `caseworkctl` helper could not inspect the Casework project.",
                "Install the matching Casework tools or provide RSTACK_CASEWORKCTL_BIN, then run the check again.",
            ).into());
        }
    };
    validate_casework_binding_ids(&plan.bindings, &facts)?;
    Ok(casework_principals_from_facts(plan, breg, &facts)?)
}

fn casework_principals_from_facts(
    plan: &Plan,
    breg: Option<&BregAuthority>,
    facts: &CaseworkFacts,
) -> plan::SemanticResult<BTreeMap<String, String>> {
    let mut principals = BTreeMap::new();
    for (name, person) in &plan.people {
        let Some(grant) = person.grants.get(&Product::Casework) else {
            continue;
        };
        let escaped = registry_platform_yaml::escape_pointer_segment(name);
        let claim = facts.profiles.get(&grant.profile).map(String::as_str).ok_or_else(|| {
            plan::SemanticRefusal::new(
                format!("/people/{escaped}/grants/casework/profile"),
                "The Casework grant profile does not name an access profile in the Casework project.",
                "Set profile to an access profile defined by the Casework project.",
            )
        })?;
        plan::require(
            matches!(claim, "sub" | "registry_principal")
                || (!plan::reserved_claim(claim)
                    && !matches!(claim, "registry_actor_kind" | "registry_purpose")),
            &format!("/people/{escaped}/grants/casework/profile"),
            "The Casework access profile selects an incompatible principal claim.",
            "Choose a Casework access profile whose principal claim is `sub`, `registry_principal`, or a non-reserved custom claim.",
        )?;
        plan::require(
            !grant.claims.contains_key(claim),
            &format!("/people/{escaped}/grants/casework/claims"),
            "The Casework grant claims cannot replace the principal claim selected by its access profile.",
            "Remove the selected principal claim from this grant's additional claims.",
        )?;
        if person.casework_context {
            plan::require(
                claim == "sub" || breg.is_some_and(|authority| authority.principal == claim),
                &format!("/people/{escaped}/caseworkContext"),
                "Casework context forwarding requires Casework to read `sub` or the BReg principal claim.",
                "Choose a compatible Casework access profile or remove caseworkContext.",
            )?;
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
            "development product inspection was interrupted"
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
    let report: Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("caseworkctl explain did not emit a JSON report"))?;
    if status.success() {
        return casework_report_facts(&report);
    }
    if status.code() == Some(1) && casework_domain_refusal(&report) {
        return Err(InvalidCaseworkProject.into());
    }
    anyhow::bail!("caseworkctl explain did not complete successfully")
}

fn casework_domain_refusal(report: &Value) -> bool {
    report["apiVersion"] == "id.registrystack.org/formats/casework/report/v1alpha2"
        && report["kind"] == "CaseworkReport"
        && report["command"] == "explain"
        && report["status"] == "domain-refusal"
        && report["ok"] == false
        && report["diagnostics"].as_array().is_some_and(|diagnostics| {
            diagnostics.iter().any(|diagnostic| {
                diagnostic["severity"] == "error"
                    && diagnostic["code"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty())
                    && diagnostic["path"].is_string()
                    && diagnostic["message"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty())
                    && diagnostic["suggestedAction"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty())
            })
        })
}

#[derive(Debug, thiserror::Error)]
#[error("the Casework project did not pass its owning validation")]
struct InvalidCaseworkProject;

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
    let profiles = report
        .pointer("/accessProfiles")
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
        os::unix::fs::PermissionsExt,
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
            "reviewPolicies": [],
            "accessProfiles": [
                {"id": "producer", "principalClaim": "producer_identity"},
                {"id": "reviewer", "principalClaim": "sub"}
            ],
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
        report["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id": "reviewer", "principalClaim": "different"}));
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

    fn authority_plan(breg_claims: Value, casework_claims: Value, context: bool) -> Plan {
        serde_json::from_value(json!({
            "issuer": "https://issuer.example.invalid",
            "products": [
                {"product": "breg", "project": "breg", "audience": "registry"},
                {"product": "casework", "project": "casework", "audience": "review"}
            ],
            "people": {"operator": {
                "subject": "operator", "client": "operator-client",
                "grants": {
                    "breg": {"profile": "operator", "scopes": [], "claims": breg_claims},
                    "casework": {"profile": "reviewer", "scopes": [], "claims": casework_claims}
                },
                "caseworkContext": context
            }},
            "journey": {"id": "smoke", "steps": []}
        }))
        .unwrap()
    }

    #[test]
    fn breg_authority_restrictions_are_typed_and_located() {
        let plan = authority_plan(json!({}), json!({}), false);
        let error = breg_principal(
            &plan,
            "/products/0/project",
            &BTreeSet::from(["registry_principal".to_owned(), "sub".to_owned()]),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("/products/0/project"), "{error}");
        assert!(
            error.contains("The BReg access profiles select more than one principal claim."),
            "{error}"
        );
        assert!(
            error.contains("Use one principal claim across the BReg project's access profiles."),
            "{error}"
        );

        let plan = authority_plan(
            json!({"registry_principal": "private-claim-marker"}),
            json!({}),
            false,
        );
        let error = breg_principal(
            &plan,
            "/products/0/project",
            &BTreeSet::from(["registry_principal".to_owned()]),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("/people/operator/grants/breg/claims"),
            "{error}"
        );
        assert!(
            error.contains("cannot replace the principal claim"),
            "{error}"
        );
        assert!(!error.contains("private-claim-marker"), "{error}");
    }

    #[test]
    fn casework_authority_restrictions_are_typed_and_located() {
        let facts = |principal: &str| CaseworkFacts {
            profiles: BTreeMap::from([("reviewer".to_owned(), principal.to_owned())]),
            trusted_producers: BTreeSet::new(),
            context_providers: BTreeSet::new(),
        };

        let plan = authority_plan(json!({}), json!({}), false);
        let error = casework_principals_from_facts(&plan, None, &facts("registry_actor_kind"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("/people/operator/grants/casework/profile"),
            "{error}"
        );
        assert!(error.contains("incompatible principal claim"), "{error}");

        let plan = authority_plan(json!({}), json!({"sub": "private-claim-marker"}), false);
        let error = casework_principals_from_facts(&plan, None, &facts("sub"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("/people/operator/grants/casework/claims"),
            "{error}"
        );
        assert!(
            error.contains("cannot replace the principal claim"),
            "{error}"
        );
        assert!(!error.contains("private-claim-marker"), "{error}");

        let plan = authority_plan(json!({}), json!({}), true);
        let breg = BregAuthority {
            principal: "registry_principal".to_owned(),
            purpose: false,
            requires_postgis: false,
            named_clients: BTreeSet::new(),
        };
        let error = casework_principals_from_facts(&plan, Some(&breg), &facts("custom_principal"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("/people/operator/caseworkContext"),
            "{error}"
        );
        assert!(
            error.contains("requires Casework to read `sub` or the BReg principal claim"),
            "{error}"
        );
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
    fn a_report_without_the_access_profile_list_is_refused() {
        let report = json!({
            "apiVersion": "id.registrystack.org/formats/casework/report/v1alpha2",
            "kind": "CaseworkReport", "command": "explain", "status": "complete", "ok": true,
            "reviewPolicies": [{"dependencies": {"accessProfiles": [
                {"id": "reviewer", "principalClaim": "sub"}
            ]}}]
        });
        assert!(casework_report_facts(&report)
            .unwrap_err()
            .to_string()
            .contains("did not report access profiles"));
    }

    #[test]
    fn a_failed_tool_leaves_its_stderr_in_an_owner_only_log_and_the_error() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        let error = run_logged_tool(
            Path::new("/bin/sh"),
            &["-c".as_ref(), "echo boom >&2; exit 3".as_ref()],
            root,
            ("breg", "test"),
            || Ok(()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("breg test failed"), "{error}");
        assert!(error.contains("boom"), "{error}");
        let logs = root.join("logs");
        let log = logs.join("breg-test.log");
        assert_eq!(fs::read_to_string(&log).unwrap(), "boom\n");
        assert!(error.contains(&log.display().to_string()), "{error}");
        assert_eq!(
            fs::metadata(&logs).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_successful_tool_leaves_no_failure_text() {
        let scratch = tempfile::tempdir().unwrap();
        run_logged_tool(
            Path::new("/bin/sh"),
            &["-c".as_ref(), "echo fine >&2".as_ref()],
            scratch.path(),
            ("breg", "test"),
            || Ok(()),
        )
        .unwrap();
    }

    #[test]
    fn the_log_tail_keeps_the_last_twenty_lines_within_four_kib() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("log");
        let lines: Vec<_> = (1..=30).map(|number| format!("line {number}")).collect();
        fs::write(&path, lines.join("\n")).unwrap();
        let tail = log_tail(&path);
        assert_eq!(tail.lines().count(), 20);
        assert!(tail.starts_with("line 11") && tail.ends_with("line 30"));

        fs::write(&path, format!("{}\nlast", "x".repeat(10_000))).unwrap();
        let tail = log_tail(&path);
        assert!(tail.len() <= 4096 && tail.ends_with("last"));

        fs::write(&path, [b'a', 0xff, b'\n', b'b']).unwrap();
        assert_eq!(log_tail(&path), "a\u{fffd}\nb");
    }

    #[test]
    fn spawned_processes_are_recorded_as_product_pid_and_group() {
        let scratch = tempfile::tempdir().unwrap();
        write_processes(
            scratch.path(),
            &[(Product::Breg, 4242), (Product::Casework, 4343)],
        )
        .unwrap();
        let path = scratch.path().join("processes.json");
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
            json!([
                {"product": "breg", "pid": 4242, "pgid": 4242},
                {"product": "casework", "pid": 4343, "pgid": 4343}
            ])
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    fn minimal_registry(edit: impl FnOnce(&str) -> String) -> registry_breg::CompiledRegistry {
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/examples/minimal");
        let scratch = tempfile::tempdir().unwrap();
        let project = scratch.path().join("project");
        copy_project(&source, &project).unwrap();
        let registry = project.join("registry.yaml");
        fs::write(&registry, edit(&fs::read_to_string(&registry).unwrap())).unwrap();
        crate::compile(&project, crate::ProfileArg::Production, "project-dev-test")
            .unwrap_or_else(|_| panic!("the edited project must compile"))
    }

    fn breg_person(profile: &str) -> plan::TestPerson {
        serde_json::from_value(json!({
            "subject": "someone", "client": "client",
            "grants": {"breg": {"profile": profile, "scopes": []}}
        }))
        .unwrap()
    }

    #[test]
    fn a_breg_grant_naming_an_unknown_profile_is_refused_at_its_pointer() {
        let registry = minimal_registry(str::to_owned);
        let people = BTreeMap::from([
            ("editor".to_owned(), breg_person("directory-editor")),
            ("typo".to_owned(), breg_person("directory-edtor")),
        ]);
        let error = check_breg_grants(&registry, &people)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("/people/typo/grants/breg/profile"),
            "{error}"
        );
        assert!(error.contains("directory-editor"), "{error}");
        let valid = BTreeMap::from([("editor".to_owned(), breg_person("directory-editor"))]);
        check_breg_grants(&registry, &valid).unwrap();
    }

    #[test]
    fn encrypted_fields_are_refused_before_provisioning() {
        let registry = minimal_registry(|source| {
            let source = source.replacen(
                "mutationMode: mutable\n    display: {label: Contact",
                "mutationMode: mutable\n    classification: restricted\n    display: {label: Contact",
                1,
            );
            source.replacen(
                "{id: email, type: string, required: true, minimumLength: 1, maximumLength: 254, classification: internal}\n      - {id: jurisdiction",
                "{id: email, type: string, required: true, minimumLength: 1, maximumLength: 254, classification: restricted, encrypted: true}\n      - {id: jurisdiction",
                1,
            )
        });
        assert_eq!(
            refuse_encrypted_fields(&registry).unwrap_err().to_string(),
            "rstack dev does not configure field encryption yet; contact.email is encrypted"
        );
        refuse_encrypted_fields(&minimal_registry(str::to_owned)).unwrap();
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
