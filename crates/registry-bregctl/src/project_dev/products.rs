// SPDX-License-Identifier: Apache-2.0
//! Activate ordinary packages and serve them on the run's private bindings.

use anyhow::{bail, ensure, Context, Result};
use registry_breg::fixtures::journey_step_profiles;
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
    guard,
    issuer::Issuer,
    operational,
    plan::{self, Plan, Product},
    private_directory, stopping, write_private, BregAuthority, Operational, RunInput, POLL,
};

/// The run's development field-encryption data key, inside the owner-only run
/// directory and removed with it.
pub(super) const FIELD_KEY: &str = "field-key";

/// How long a started product has to answer `/ready`.
const READINESS_WAIT: Duration = Duration::from_secs(30);

/// The run's field-encryption key file, when the run wrote one, so recovery
/// can name it for removal.
pub(super) fn field_key_file(root: &Path) -> Option<PathBuf> {
    let path = root.join(FIELD_KEY);
    fs::symlink_metadata(&path).is_ok().then_some(path)
}

pub(super) struct ProductRunner<'a> {
    input: Arc<RunInput>,
    root: &'a Path,
    terminate: &'a AtomicBool,
    deadline: Instant,
    runtime: tokio::runtime::Runtime,
    http: reqwest::Client,
    children: Vec<(Product, guard::Child)>,
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
            let project = self.input.project.join(&entry.project);
            if entry.product == Product::Messaging {
                self.tool(
                    entry.product,
                    "check",
                    &["--project".as_ref(), project.as_os_str()],
                )?;
            } else {
                self.tool(entry.product, "check", &[project.as_os_str()])?;
            }
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
            .context("reserve loopback listeners")
            .map_err(operational)?;
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
                Product::Messaging => self.activate_messaging(database, &project, bind)?,
            };
            let binaries = &self.input.binaries[&product];
            let mut command = guard::Command::new(
                self.root,
                &format!("runtime-{}", product.name()),
                &binaries.runtime,
            )
            .map_err(operational)?;
            command.arg("--runtime-config").arg(config);
            if matches!(product, Product::Casework | Product::Messaging) {
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
                .with_context(|| format!("cannot start {}", product.name()))
                .map_err(operational)?;
            self.children.push((product, child));
            self.record_processes()?;
            self.ready(product, url, READINESS_WAIT)?;
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
        self.write_field_key()?;
        // A server that cannot provision, for example without PostGIS or the
        // privilege to create it, is an environment failure.
        let rehearsal = database
            .provision("breg_test", true, requires_postgis)
            .map_err(operational)?;
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
        let urls = database
            .provision("breg", true, requires_postgis)
            .map_err(operational)?;
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

    /// Draw the run's own data key when the project encrypts fields. BReg's
    /// key generator creates the file owner-only from the platform random
    /// source; the key is read only by the runtime through its `secret:file`
    /// reference.
    fn write_field_key(&self) -> Result<()> {
        if !self.encrypts_fields() {
            return Ok(());
        }
        crate::field_encryption::keygen(&self.root.join(FIELD_KEY))
            .map(drop)
            .map_err(|error| {
                Operational(format!(
                    "cannot write the development run's field-encryption key into its run \
                     directory: {error}"
                ))
                .into()
            })
    }

    fn encrypts_fields(&self) -> bool {
        self.input
            .breg_authority
            .as_ref()
            .is_some_and(|authority| authority.encrypts_fields)
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
        let urls = database
            .provision("casework", false, false)
            .map_err(operational)?;
        let config = self.config(Product::Casework, "casework", bind, &package, urls)?;
        let arguments = ["--runtime-config".as_ref(), config.as_os_str()];
        self.tool(Product::Casework, "apply", &arguments)?;
        self.tool(Product::Casework, "doctor", &arguments)?;
        Ok(config)
    }

    fn activate_messaging(
        &self,
        database: &mut Database,
        project: &Path,
        bind: &str,
    ) -> Result<PathBuf> {
        let package = self.root.join("messaging-package");
        self.tool(
            Product::Messaging,
            "package",
            &[
                project.as_os_str(),
                "--output".as_ref(),
                package.as_os_str(),
            ],
        )?;
        let urls = database
            .provision("messaging", false, false)
            .map_err(operational)?;
        let config = self.config(Product::Messaging, "messaging", bind, &package, urls)?;
        let arguments = ["--runtime-config".as_ref(), config.as_os_str()];
        self.tool(Product::Messaging, "apply", &arguments)?;
        self.tool(Product::Messaging, "status", &arguments)?;
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
        let plan = &self.input.plan;
        self.secret(&format!("{name}-runtime-url"), urls.runtime.as_bytes())?;
        self.secret(&format!("{name}-migration-url"), urls.migration.as_bytes())?;
        self.secret(&format!("{name}-audit-key"), random_secret()?.as_bytes())?;
        let identity = format!("dev-{}-{name}", self.input.run_id);
        let mut config = match product {
            Product::Breg => {
                let authority = self.input.breg_authority.as_ref().expect("BReg authority");
                let (mut config, mut oidc) = shared_config(
                    plan,
                    product,
                    name,
                    self.root,
                    package,
                    &authority.named_clients,
                );
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
                if name == "breg" && authority.requires_postgis {
                    config["listener"]["publicOrigin"] = json!(format!("http://{bind}"));
                }
                // A development run initializes a disposable local database, as
                // `bregctl dev` does; BReg accepts local-file key custody only
                // for that environment.
                config["identity"] = json!({
                    "environment": "local", "instanceId": identity,
                    "databaseId": identity, "databaseInitializationEnvironment": "local"
                });
                if authority.encrypts_fields {
                    config["fieldEncryption"] = json!({"provider": {
                        "type": "local-file", "dekRef": format!("secret:file/{FIELD_KEY}")
                    }});
                }
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
                config
            }
            Product::Casework => casework_config(plan, name, self.root, package, &identity, bind),
            Product::Messaging => messaging_config(
                plan,
                name,
                self.root,
                package,
                &identity,
                bind,
                &self.input.messaging_clients,
            ),
        };
        if let Some(bindings) = &self.bindings {
            bindings.configure(product, &mut config);
        }
        let path = self.root.join(format!("{name}-runtime.yaml"));
        write_private(&path, &serde_json::to_vec(&config)?)?;
        Ok(path)
    }

    fn secret(&self, name: &str, bytes: &[u8]) -> Result<String> {
        write_private(&self.root.join(name), bytes)?;
        Ok(secret_ref(name))
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

    /// Record every live runtime group for status diagnostics and manual
    /// cleanup evidence. Guards, not this record, own process lifetime.
    fn record_processes(&self) -> Result<()> {
        let entries: Vec<_> = self
            .children
            .iter()
            .map(|(product, child)| (*product, child.id()))
            .collect();
        write_processes(self.root, &entries)
    }

    fn ready(&mut self, product: Product, base: &str, wait: Duration) -> Result<()> {
        let end = Instant::now() + wait;
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
            if Instant::now() >= end {
                return Err(operational(anyhow::anyhow!(
                    "{} did not become ready{}",
                    product.name(),
                    self.runtime_log_tail(product)
                )));
            }
            thread::sleep(POLL);
        }
    }

    /// Fail while waiting on `waiting`, naming whichever child exited.
    fn ensure_alive(&self, waiting: Product) -> Result<()> {
        for (product, child) in &self.children {
            if child.exited()? {
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
            if child.exited()? {
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
        if Instant::now() >= self.deadline {
            return Err(operational(anyhow::anyhow!(
                "development run did not start within five minutes"
            )));
        }
        Ok(())
    }

    pub(super) fn stop(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        self.children.retain_mut(|(product, child)| {
            if child.stop().is_err() {
                failures.push(product.name());
                true
            } else {
                false
            }
        });
        // Drop reaped groups from the diagnostic record. Recovery waits on
        // guard locks and lifecycle receipts rather than signaling these IDs.
        self.record_processes()?;
        ensure!(failures.is_empty(), "cannot stop {}", failures.join(", "));
        let incomplete = guard::incomplete_launches(self.root)?;
        ensure!(
            incomplete.is_empty(),
            "process guards did not confirm cleanup for {}",
            incomplete.join(", ")
        );
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
    let mut command = guard::Command::new(root, &format!("tool-{product}-{stage}"), binary)
        .map_err(operational)?;
    let mut child = command
        .args(args)
        .stdout(output.try_clone()?)
        .stderr(open_log(root, &name)?)
        .spawn()
        .with_context(|| format!("cannot start {product} {stage}"))
        .map_err(operational)?;
    let status = wait_for_guarded_tool(&mut child, active)?;
    logged_tool_result(status, &mut output, root, (product, stage))
}

fn logged_tool_result(
    status: ExitStatus,
    output: &mut fs::File,
    root: &Path,
    (product, stage): (&str, &str),
) -> Result<()> {
    if status.success() {
        return Ok(());
    }
    output.rewind()?;
    let codes = report_codes(output)?;
    bail!(
        "{product} {stage} failed{codes}{}",
        failure_detail(&log_path(root, &format!("{product}-{stage}")))
    );
}

/// Exercise the log/result boundary in unit tests without routing a shell
/// through the Rust test harness as if it were the bregctl binary. The native
/// lifecycle test covers the real hidden guard dispatch.
#[cfg(test)]
fn run_logged_tool_direct(
    binary: &Path,
    args: &[&std::ffi::OsStr],
    root: &Path,
    (product, stage): (&str, &str),
) -> Result<()> {
    let name = format!("{product}-{stage}");
    let mut output = tempfile::tempfile_in(root)?;
    let mut child = child_command(binary)
        .args(args)
        .stdout(output.try_clone()?)
        .stderr(open_log(root, &name)?)
        .spawn()?;
    let status = wait_for_tool(&mut child, || Ok(()))?;
    logged_tool_result(status, &mut output, root, (product, stage))
}

/// Record each runtime process group and the start time of its leader for
/// diagnostics and an operator's manual cleanup decision. Children start as
/// group leaders, so the group ID is the PID.
fn write_processes(root: &Path, children: &[(Product, u32)]) -> Result<()> {
    let table = super::recovery::process_table()?;
    let entries: Vec<_> = children
        .iter()
        .map(|(product, pid)| {
            let started = table
                .iter()
                .find(|row| row.pid == *pid)
                .map(|row| &row.started);
            json!({"product": product.name(), "pid": pid, "pgid": pid, "started": started})
        })
        .collect();
    write_private(&root.join("processes.json"), &serde_json::to_vec(&entries)?)
}

/// The reference to the secret the run writes as `name` in its directory.
fn secret_ref(name: &str) -> String {
    format!("secret:file/{name}")
}

/// The members both products' runtime configurations share, and the OIDC
/// settings each completes. They name the run's secrets by reference only:
/// `config` writes the secrets beside them.
fn shared_config(
    plan: &Plan,
    product: Product,
    name: &str,
    root: &Path,
    package: &Path,
    extra_clients: &BTreeSet<String>,
) -> (Value, Value) {
    let clients: BTreeSet<_> = plan
        .people
        .values()
        .filter(|person| person.grants.contains_key(&product))
        .map(|person| person.client.as_str())
        .chain(
            plan.workloads
                .values()
                .filter(|workload| workload.product == product)
                .map(|workload| workload.client.as_str()),
        )
        .chain(extra_clients.iter().map(String::as_str))
        .collect();
    let oidc = json!({
        "issuer": plan.issuer,
        "audience": plan.product(product).audience,
        "allowedClients": clients,
        "scopeClaim": "scope",
        "jwksSource": {"type": "static", "documentRef": secret_ref("jwks")}
    });
    let mut database = json!({
        "runtimeUrlRef": secret_ref(&format!("{name}-runtime-url")),
        "migrationUrlRef": secret_ref(&format!("{name}-migration-url"))
    });
    if root.join("postgres-ca").is_file() {
        database["trustedRootCertificateRef"] = json!(secret_ref("postgres-ca"));
    }
    let audit = json!({
        "hashKeyRef": secret_ref(&format!("{name}-audit-key")),
        "path": root.join(format!("{name}-audit")).join("audit.jsonl"),
    });
    let config = json!({
        "package": {"root": package},
        "secretProviders": {"file": {"root": root}},
        "database": database,
        "audit": audit,
    });
    (config, oidc)
}

/// The Casework runtime configuration the run writes, before its bindings.
/// `check` renders it with stand-in paths, so the configuration Casework
/// checks is the one `start` writes.
fn casework_config(
    plan: &Plan,
    name: &str,
    root: &Path,
    package: &Path,
    identity: &str,
    bind: &str,
) -> Value {
    let (mut config, oidc) = shared_config(
        plan,
        Product::Casework,
        name,
        root,
        package,
        &BTreeSet::new(),
    );
    config["apiVersion"] = json!("id.registrystack.org/formats/casework/runtime/v1alpha1");
    config["kind"] = json!("CaseworkRuntimeConfig");
    config["listener"] = json!({"bind": bind, "tlsTermination": "development-loopback"});
    config["identity"] = json!({"databaseId": identity});
    config["authentication"] = json!({"oidc": oidc});
    config
}

/// Messaging keeps its own package, database roles, runtime listener and
/// authorization boundary. A project provider without a run-local connection
/// remains deliberately unconfigured; the smoke journey proves acceptance and
/// receipt storage without introducing another broker.
fn messaging_config(
    plan: &Plan,
    name: &str,
    root: &Path,
    package: &Path,
    identity: &str,
    bind: &str,
    clients: &BTreeSet<String>,
) -> Value {
    let (mut config, oidc) = shared_config(plan, Product::Messaging, name, root, package, clients);
    config["apiVersion"] = json!("id.registrystack.org/formats/messaging/runtime/v1alpha1");
    config["kind"] = json!("MessagingRuntimeConfig");
    config["identity"] = json!({"databaseId": identity});
    config["listener"] = json!({
        "bind": bind,
        "tlsTermination": "development-loopback",
        "networkExposure": "private-address"
    });
    config["authentication"] = json!({"oidc": oidc});
    config["audit"]["destination"] = json!("file");
    config["audit"]["path"] = json!(root.join("messaging-audit.jsonl"));
    config["retention"] = json!({
        "payloadRetentionDays": 1,
        "recordRetentionDays": 1,
        "receiptRetentionDays": 1
    });
    config
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
    pub(super) messaging_clients: BTreeSet<String>,
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

/// The error for an inspection that could not complete. An interrupt is the
/// operator's request and stays as it is. Any other failure is an unavailable
/// inspection whose reason keeps the cause; the cause comes from spawning the
/// tool, its timeout, temporary files and the report parse, and none of those
/// messages carries a configured value.
fn inspection_failed(
    field: &str,
    action: &str,
    error: anyhow::Error,
    terminate: &AtomicBool,
) -> anyhow::Error {
    if terminate.load(Ordering::Relaxed) {
        return error;
    }
    InspectionUnavailable::new(
        field,
        &format!("The selected `caseworkctl` helper could not {action}: {error:#}."),
        "Install the matching Casework tools or provide RSTACK_CASEWORKCTL_BIN, then run the check again.",
    )
    .into()
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
    super::bindings::check_with_breg_reader(plan)?;
    let breg_authority = breg_authority(root, plan)?;
    let casework_principals = casework_principals(root, plan, breg_authority.as_ref(), terminate)?;
    let messaging_clients = check_messaging_project(root, plan, terminate)?;
    Ok(ProductInspection {
        breg_authority,
        casework_principals,
        messaging_clients,
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
        Product::Messaging => "messaging.yaml",
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
    check_breg_workloads(&registry, &plan.workloads)?;
    let inventory = registry_breg::authority::authority_inventory(&registry)?;
    let principal = breg_principal(plan, &project.field, &inventory.principal_claims)?;
    Ok(Some(BregAuthority {
        principal,
        purpose: inventory.purpose_required,
        named_clients: crate::identity_facts::named_requester_clients(&registry),
        requires_postgis: breg_requires_postgis(&registry),
        encrypts_fields: breg_encrypts_fields(&registry),
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
    for (name, workload) in &plan.workloads {
        if workload.product == Product::Breg {
            plan::require(
                !workload.grant.claims.contains_key(&principal),
                &format!(
                    "/workloads/{}/grant/claims",
                    registry_platform_yaml::escape_pointer_segment(name)
                ),
                "The BReg workload claims cannot replace the principal claim selected by the BReg project.",
                "Remove the selected principal claim from this workload's additional claims.",
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

/// The runtime needs a field-encryption provider exactly when the compiled
/// project declares an encrypted field.
fn breg_encrypts_fields(registry: &registry_breg::CompiledRegistry) -> bool {
    registry.entities().values().any(|entity| {
        entity
            .fields
            .values()
            .any(|field| field.encryption.is_some())
    })
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
                "Set profile to an access profile defined by the BReg project.",
            )?;
        }
    }
    Ok(())
}

fn check_breg_workloads(
    registry: &registry_breg::CompiledRegistry,
    workloads: &BTreeMap<String, plan::Workload>,
) -> plan::SemanticResult<()> {
    let profiles: BTreeSet<_> = registry
        .access_profile_displays()
        .iter()
        .map(|profile| profile.id.as_str())
        .collect();
    for (name, workload) in workloads {
        if workload.product == Product::Breg {
            plan::require(
                profiles.contains(workload.grant.profile.as_str()),
                &format!(
                    "/workloads/{}/grant/profile",
                    registry_platform_yaml::escape_pointer_segment(name)
                ),
                "The BReg workload profile does not name an access profile in the BReg project.",
                "Set profile to an access profile defined by the BReg project.",
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
        Err(error) => {
            return Err(inspection_failed(
                &project.field,
                "inspect the Casework project",
                error,
                terminate,
            ));
        }
    };
    let status_profile = plan
        .bindings
        .casework_context_provider
        .as_ref()
        .and_then(|binding| plan.people.get(&binding.identity))
        .and_then(|person| person.grants.get(&Product::Breg))
        .map(|grant| grant.profile.as_str());
    validate_casework_binding_ids(&plan.bindings, &facts, status_profile)?;
    if let Some(binding) = &plan.bindings.casework_context_provider {
        check_casework_binding(&tool, &project, plan, binding, terminate)?;
    }
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

#[derive(Debug, Eq, PartialEq)]
struct MessagingProfile {
    principal_claim: String,
    scopes: BTreeSet<String>,
    clients: BTreeSet<String>,
    actor_kind: Option<String>,
    sender: bool,
}

fn check_messaging_project(
    root: &Path,
    plan: &Plan,
    terminate: &AtomicBool,
) -> Result<BTreeSet<String>> {
    let Some(project) = product_root(root, plan, Product::Messaging)? else {
        return Ok(BTreeSet::new());
    };
    let tool = super::product_tool(Product::Messaging).map_err(|_| {
        InspectionUnavailable::new(
            &project.field,
            "The Messaging project cannot be inspected because its owning tool is unavailable.",
            "Install the matching Messaging tools or provide RSTACK_MESSAGINGCTL_BIN, then run the check again.",
        )
    })?;
    let checked = tool_report(
        &tool,
        "messagingctl",
        "check",
        &["--project".as_ref(), project.root.as_os_str()],
        terminate,
    );
    let (status, report) = match checked {
        Ok(checked) => checked,
        Err(error) if terminate.load(Ordering::Relaxed) => return Err(error),
        Err(error) => {
            return Err(InspectionUnavailable::new(
                &project.field,
                &format!(
                    "The selected `messagingctl` helper could not inspect the Messaging project: {error:#}."
                ),
                "Install the matching Messaging tools or provide RSTACK_MESSAGINGCTL_BIN, then run the check again.",
            )
            .into())
        }
    };
    if status.code() == Some(1) && messaging_domain_refusal(&report) {
        return Err(plan::SemanticRefusal::new(
            &project.field,
            "The Messaging project did not pass validation by its owning tool.",
            "Run `messagingctl check --project PROJECT` for authored diagnostics, then correct the Messaging project.",
        )
        .into());
    }
    if !status.success() {
        return Err(InspectionUnavailable::new(
            &project.field,
            "The selected `messagingctl` helper did not complete the Messaging project check.",
            "Install the matching Registry Stack Messaging tools, then run the check again.",
        )
        .into());
    }
    let profiles = messaging_report_profiles(&report).map_err(|error| {
        InspectionUnavailable::new(
            &project.field,
            &format!(
                "The selected `messagingctl` helper returned an incompatible report: {error:#}."
            ),
            "Install the matching Registry Stack Messaging tools, then run the check again.",
        )
    })?;
    validate_messaging_grants(plan, &profiles)?;
    Ok(profiles
        .values()
        .flat_map(|profile| profile.clients.iter().cloned())
        .collect())
}

fn messaging_domain_refusal(report: &Value) -> bool {
    report["apiVersion"] == "id.registrystack.org/formats/messaging/ctl-report/v1alpha1"
        && report["kind"] == "MessagingCtlReport"
        && report["command"] == "check"
        && report["status"] == "domain-refusal"
        && report["ok"] == false
        && report["diagnostics"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
}

fn messaging_report_profiles(report: &Value) -> Result<BTreeMap<String, MessagingProfile>> {
    ensure!(
        report["apiVersion"] == "id.registrystack.org/formats/messaging/ctl-report/v1alpha1"
            && report["kind"] == "MessagingCtlReport"
            && report["command"] == "check"
            && report["status"] == "complete"
            && report["ok"] == true,
        "messagingctl check returned an incompatible envelope"
    );
    let entries = report["accessProfiles"]
        .as_array()
        .context("messagingctl check did not report access profiles")?;
    let mut profiles = BTreeMap::new();
    for entry in entries {
        let id = entry["id"]
            .as_str()
            .context("a Messaging access profile has no ID")?;
        let principal_claim = entry["principalClaim"]
            .as_str()
            .filter(|claim| !claim.is_empty())
            .context("a Messaging access profile has no principal claim")?;
        let string_set = |member: &str| -> Result<BTreeSet<String>> {
            let values: Vec<String> = entry[member]
                .as_array()
                .with_context(|| format!("a Messaging access profile has no {member}"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .with_context(|| {
                            format!("a Messaging access profile has an invalid {member} value")
                        })
                })
                .collect::<Result<_>>()?;
            let unique: BTreeSet<String> = values.iter().cloned().collect();
            ensure!(
                unique.len() == values.len(),
                "a Messaging access profile has duplicate {member} values"
            );
            Ok(unique)
        };
        let actor_kind = match entry.get("actorKind") {
            Some(Value::Null) => None,
            Some(Value::String(kind)) if matches!(kind.as_str(), "human" | "agent" | "service") => {
                Some(kind.clone())
            }
            _ => bail!("a Messaging access profile has an invalid actorKind"),
        };
        let acts_as = entry["actsAs"]
            .as_str()
            .context("a Messaging access profile has no actsAs value")?;
        ensure!(
            matches!(acts_as, "sender" | "operator"),
            "a Messaging access profile has an invalid actsAs value"
        );
        let profile = MessagingProfile {
            principal_claim: principal_claim.to_owned(),
            scopes: string_set("requiredScopes")?,
            clients: string_set("requesterClients")?,
            actor_kind,
            sender: acts_as == "sender",
        };
        ensure!(
            profiles.insert(id.to_owned(), profile).is_none(),
            "messagingctl check returned duplicate access profiles"
        );
    }
    Ok(profiles)
}

fn validate_messaging_grant(
    field: &str,
    client_field: &str,
    grant: &plan::Grant,
    client: &str,
    profiles: &BTreeMap<String, MessagingProfile>,
    workload: bool,
) -> plan::SemanticResult<()> {
    let profile = profiles.get(&grant.profile).ok_or_else(|| {
        plan::SemanticRefusal::new(
            format!("{field}/profile"),
            "The Messaging grant profile does not name an access profile in the Messaging project.",
            "Set profile to an access profile defined by the Messaging project.",
        )
    })?;
    plan::require(
        profile.principal_claim == "sub",
        &format!("{field}/profile"),
        "The local Messaging runner requires a profile whose principalClaim is `sub`.",
        "Use a Messaging profile bound to `sub`, so receipt ownership remains the service subject.",
    )?;
    plan::require(
        profile.clients.contains(client),
        client_field,
        "The Messaging grant client is not admitted by its access profile.",
        "Set client to one of the profile's requesterClients.",
    )?;
    plan::require(
        grant.scopes.iter().cloned().collect::<BTreeSet<_>>() == profile.scopes,
        &format!("{field}/scopes"),
        "The Messaging grant scopes differ from the access profile's requiredScopes.",
        "Set scopes to exactly the Messaging access profile's requiredScopes.",
    )?;
    if let Some(kind) = &profile.actor_kind {
        plan::require(
            grant
                .claims
                .get("registry_actor_kind")
                .and_then(Value::as_str)
                == Some(kind),
            &format!("{field}/claims/registry_actor_kind"),
            "The Messaging grant actor kind differs from the access profile.",
            "Set registry_actor_kind to the actorKind required by the Messaging access profile.",
        )?;
    }
    if workload {
        plan::require(
            profile.sender,
            &format!("{field}/profile"),
            "A Messaging workload connection must use a sender access profile.",
            "Select a Messaging profile whose actsAs value is sender.",
        )?;
    }
    Ok(())
}

fn validate_messaging_grants(
    plan: &Plan,
    profiles: &BTreeMap<String, MessagingProfile>,
) -> plan::SemanticResult<()> {
    for (name, person) in &plan.people {
        if let Some(grant) = person.grants.get(&Product::Messaging) {
            let field = format!(
                "/people/{}/grants/messaging",
                registry_platform_yaml::escape_pointer_segment(name)
            );
            let client_field = format!(
                "/people/{}/client",
                registry_platform_yaml::escape_pointer_segment(name)
            );
            validate_messaging_grant(
                &field,
                &client_field,
                grant,
                &person.client,
                profiles,
                false,
            )?;
        }
    }
    for (name, workload) in &plan.workloads {
        if workload.product == Product::Messaging {
            let field = format!(
                "/workloads/{}",
                registry_platform_yaml::escape_pointer_segment(name)
            );
            validate_messaging_grant(
                &format!("{field}/grant"),
                &format!("{field}/client"),
                &workload.grant,
                &workload.client,
                profiles,
                true,
            )?;
        }
    }
    Ok(())
}

fn explain_casework_facts(
    tool: &Path,
    project: &Path,
    terminate: &AtomicBool,
) -> Result<CaseworkFacts> {
    let (status, report) = tool_report(
        tool,
        "caseworkctl",
        "explain",
        &[project.as_os_str()],
        terminate,
    )?;
    if status.success() {
        return casework_report_facts(&report);
    }
    if status.code() == Some(1) && casework_domain_refusal(&report, "explain") {
        return Err(InvalidCaseworkProject.into());
    }
    anyhow::bail!("caseworkctl explain did not complete successfully")
}

/// Runs a product tool's JSON command and returns its exit status with the
/// report it printed.
fn tool_report(
    tool: &Path,
    tool_name: &str,
    command: &str,
    arguments: &[&std::ffi::OsStr],
    terminate: &AtomicBool,
) -> Result<(ExitStatus, Value)> {
    const MAX_REPORT: u64 = 4 * 1024 * 1024;

    let mut child = child_command(tool)
        .args(["--format", "json", command])
        .args(arguments)
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot start {tool_name} {command}"))?;
    let stdout = child.stdout.take().expect("the report output was piped");
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
        ensure!(Instant::now() < deadline, "{tool_name} {command} timed out");
        Ok(())
    })?;
    let bytes = reader
        .join()
        .map_err(|_| anyhow::anyhow!("cannot collect the {tool_name} {command} report"))??;
    ensure!(
        bytes.len() as u64 <= MAX_REPORT,
        "the {tool_name} {command} report exceeds the size limit"
    );
    let report = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("{tool_name} {command} did not emit a JSON report"))?;
    Ok((status, report))
}

fn casework_domain_refusal(report: &Value, command: &str) -> bool {
    report["apiVersion"] == "id.registrystack.org/formats/casework/report/v1alpha2"
        && report["kind"] == "CaseworkReport"
        && report["command"] == command
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

/// The listener `check` renders the Casework configuration with. Nothing
/// binds it.
const CHECK_BIND: &str = "127.0.0.1:1";

/// Renders the Casework runtime configuration the run writes and lets the
/// selected `caseworkctl check` decide whether Casework would accept the
/// context provider binding in it. A refusal lands on the plan field that
/// produced the member Casework names.
fn check_casework_binding(
    tool: &Path,
    project: &SelectedProduct,
    plan: &Plan,
    binding: &super::bindings::CaseworkContextProvider,
    terminate: &AtomicBool,
) -> Result<()> {
    let action = "check the Casework configuration the run writes";
    let checked = (|| {
        let directory = tempfile::tempdir()?;
        // The runtime loader refuses a file reached through a symbolic link,
        // as the default temporary directory is on some systems.
        let root = directory.path().canonicalize()?;
        let mut config = casework_config(
            plan,
            "casework",
            &root,
            &root.join("casework-package"),
            "dev-check-casework",
            CHECK_BIND,
        );
        super::bindings::render_for_check(plan, Product::Casework, &mut config);
        let path = root.join("casework-runtime.yaml");
        write_private(&path, &serde_json::to_vec(&config)?)?;
        tool_report(
            tool,
            "caseworkctl",
            "check",
            &[
                project.root.as_os_str(),
                "--runtime-config".as_ref(),
                path.as_os_str(),
            ],
            terminate,
        )
    })();
    let (status, report) = match checked {
        Ok(checked) => checked,
        Err(error) => return Err(inspection_failed(&project.field, action, error, terminate)),
    };
    match casework_binding_check(status.code(), &report, &binding.id) {
        BindingCheck::Accepted => Ok(()),
        BindingCheck::Refused { member, message } => Err(plan::SemanticRefusal::new(
            super::bindings::casework_binding_field(plan, binding, &member),
            format!(
                "Casework refuses the binding configuration the run writes from this value: {}.",
                message.trim_end_matches('.')
            ),
            "Correct the value so the product accepts the configuration the run writes for this binding.",
        )
        .into()),
        BindingCheck::Unchecked => Err(inspection_failed(
            &project.field,
            action,
            anyhow::anyhow!("caseworkctl check did not report a result for the binding"),
            terminate,
        )),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum BindingCheck {
    Accepted,
    /// Casework refused `member`, a JSON pointer relative to the binding.
    Refused {
        member: String,
        message: String,
    },
    /// Casework did not read the binding.
    Unchecked,
}

/// What a `caseworkctl check` that exited with `code` and printed `report`
/// decided about the context provider binding `id` in the configuration the
/// run writes. Only refusals at the binding count: the rest of the file names
/// stand-in paths and the project is not yet paired, and `start` checks both
/// as they are. A refusal by the shared loader elsewhere in the file means
/// Casework never read the binding.
fn casework_binding_check(code: Option<i32>, report: &Value, id: &str) -> BindingCheck {
    if code == Some(0)
        && report["apiVersion"] == "id.registrystack.org/formats/casework/report/v1alpha2"
        && report["kind"] == "CaseworkReport"
        && report["command"] == "check"
        && report["status"] == "complete"
        && report["ok"] == true
    {
        return BindingCheck::Accepted;
    }
    if code != Some(1) || !casework_domain_refusal(report, "check") {
        return BindingCheck::Unchecked;
    }
    let binding = format!(
        "/contextProviders/{}",
        registry_platform_yaml::escape_pointer_segment(id)
    );
    let mut unread = false;
    for diagnostic in report["diagnostics"].as_array().into_iter().flatten() {
        if diagnostic["severity"] != "error" || diagnostic["artifact"] != "CaseworkRuntimeConfig" {
            continue;
        }
        let (Some(path), Some(code), Some(message)) = (
            diagnostic["path"].as_str(),
            diagnostic["code"].as_str(),
            diagnostic["message"].as_str(),
        ) else {
            return BindingCheck::Unchecked;
        };
        if let Some(member) = path.strip_prefix(&binding) {
            if member.is_empty() || member.starts_with('/') {
                return BindingCheck::Refused {
                    member: member.to_owned(),
                    message: message.to_owned(),
                };
            }
        }
        unread |= !code.starts_with("casework.runtime.");
    }
    if unread {
        BindingCheck::Unchecked
    } else {
        BindingCheck::Accepted
    }
}

#[derive(Debug, thiserror::Error)]
#[error("the Casework project did not pass its owning validation")]
struct InvalidCaseworkProject;

#[derive(Debug, Eq, PartialEq)]
struct CaseworkFacts {
    profiles: BTreeMap<String, String>,
    trusted_producers: BTreeSet<String>,
    /// Each context provider's ID with the profile its policy names for the
    /// `service-status` capability, when it names one.
    context_providers: BTreeMap<String, Option<String>>,
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
        context_providers: casework_context_providers(report)?,
    })
}

fn casework_context_providers(report: &Value) -> Result<BTreeMap<String, Option<String>>> {
    let entries = report["contextProviders"]
        .as_array()
        .context("caseworkctl explain did not report contextProviders")?;
    let mut providers = BTreeMap::new();
    for entry in entries {
        let id = entry["id"]
            .as_str()
            .context("a caseworkctl explain contextProviders entry has no ID")?;
        let status_profile = entry["serviceProfiles"]["service-status"]
            .as_str()
            .map(str::to_owned);
        ensure!(
            providers.insert(id.to_owned(), status_profile).is_none(),
            "caseworkctl explain returned duplicate contextProviders IDs"
        );
    }
    Ok(providers)
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
    status_profile: Option<&str>,
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
            facts.context_providers.contains_key(&binding.id),
            "/bindings/caseworkContextProvider/id",
            "The Casework context provider ID does not name a context provider in the Casework project.",
            "Set id to a context provider defined by the Casework project.",
        )?;
        // The run writes the identity's BReg grant profile as the provider's
        // status profile, and Casework refuses a provider whose binding and
        // policy disagree. Refusing here keeps that from surfacing at start.
        let policy_profile = facts.context_providers[&binding.id].as_deref();
        plan::require(
            policy_profile == status_profile,
            &format!(
                "/people/{}/grants/breg/profile",
                registry_platform_yaml::escape_pointer_segment(&binding.identity)
            ),
            "The BReg grant profile is not the service-status profile the Casework context provider names.",
            "Set the grant profile to the service-status profile in the Casework context provider's serviceProfiles.",
        )?;
    }
    Ok(())
}

impl Drop for ProductRunner<'_> {
    fn drop(&mut self) {
        // The normal exit reports stop failures explicitly.
        for (_, child) in &mut self.children {
            let _ = child.stop();
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

fn wait_for_tool(child: &mut Child, active: impl Fn() -> Result<()>) -> Result<ExitStatus> {
    loop {
        if let Err(error) = active() {
            guard::stop_direct_child(child)?;
            return Err(error);
        }
        if guard::direct_child_exited(child)? {
            return guard::stop_direct_child(child);
        }
        thread::sleep(POLL);
    }
}

fn wait_for_guarded_tool(
    child: &mut guard::Child,
    active: impl Fn() -> Result<()>,
) -> Result<ExitStatus> {
    loop {
        if let Err(error) = active() {
            child.stop()?;
            return Err(error);
        }
        if child.exited()? {
            return child.stop();
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
            context_providers: BTreeMap::new(),
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
            encrypts_fields: false,
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
            "reviewPolicies": [],
            "accessProfiles": [{"id": "reviewer", "principalClaim": "sub"}],
            "trustedProducers": [{"id": "review-producer"}],
            "contextProviders": [{
                "id": "proposal-context",
                "serviceProfiles": {"service-status": "status-reader"}
            }]
        });
        let facts = casework_report_facts(&report).unwrap();
        validate_casework_binding_ids(&bindings, &facts, Some("status-reader")).unwrap();

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
            let error = validate_casework_binding_ids(&bindings, &facts, Some("status-reader"))
                .unwrap_err()
                .to_string();
            assert!(error.contains(field), "{error}");
            assert!(error.contains(reason), "{error}");
            assert!(error.contains(action), "{error}");
            assert!(!error.contains("review-producer"), "{error}");
            assert!(!error.contains("proposal-context"), "{error}");
            report[member] = match member {
                "trustedProducers" => json!([{"id": "review-producer"}]),
                "contextProviders" => json!([{
                    "id": "proposal-context",
                    "serviceProfiles": {"service-status": "status-reader"}
                }]),
                _ => unreachable!(),
            };
        }
    }

    #[test]
    fn the_status_profile_the_run_writes_must_match_the_context_provider_policy() {
        let bindings = product_bindings();
        let report = |service_profiles: Value| {
            json!({
                "apiVersion": "id.registrystack.org/formats/casework/report/v1alpha2",
                "kind": "CaseworkReport", "command": "explain", "status": "complete", "ok": true,
                "accessProfiles": [], "trustedProducers": [{"id": "review-producer"}],
                "contextProviders": [{"id": "proposal-context", "serviceProfiles": service_profiles}]
            })
        };
        for (profiles, written) in [
            (json!({"service-status": "other-profile"}), "status-reader"),
            (json!({}), "status-reader"),
            (json!({"service-status": "status-reader"}), "other-profile"),
        ] {
            let facts = casework_report_facts(&report(profiles)).unwrap();
            let error = validate_casework_binding_ids(&bindings, &facts, Some(written))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("/people/context-reader/grants/breg/profile"),
                "{error}"
            );
            assert!(error.contains("service-status profile"), "{error}");
            assert!(!error.contains("other-profile"), "{error}");
        }
    }

    #[test]
    fn only_a_casework_refusal_at_the_binding_refuses_the_binding() {
        let report = |status: &str, diagnostics: Value| {
            json!({
                "apiVersion": "id.registrystack.org/formats/casework/report/v1alpha2",
                "kind": "CaseworkReport", "command": "check", "status": status,
                "ok": status == "complete", "diagnostics": diagnostics
            })
        };
        let diagnostic = |artifact: &str, code: &str, path: &str| {
            json!({
                "severity": "error", "code": code, "artifact": artifact, "path": path,
                "message": "the rule", "suggestedAction": "Correct it."
            })
        };
        let runtime = "CaseworkRuntimeConfig";
        let refused = |member: &str| BindingCheck::Refused {
            member: member.to_owned(),
            message: "the rule".to_owned(),
        };
        for (code, diagnostics, expected) in [
            (Some(0), json!([]), BindingCheck::Accepted),
            (
                Some(1),
                json!([diagnostic(
                    runtime,
                    "casework.runtime.invalid-context-provider",
                    "/contextProviders/registry/resource"
                )]),
                refused("/resource"),
            ),
            (
                Some(1),
                json!([diagnostic(
                    runtime,
                    "config.invalid-value",
                    "/contextProviders/registry/baseUrl"
                )]),
                refused("/baseUrl"),
            ),
            (
                Some(1),
                json!([diagnostic(
                    runtime,
                    "casework.runtime.unknown",
                    "/contextProviders/registry"
                )]),
                refused(""),
            ),
            // Another provider, Casework rules about the stand-in files or
            // the unpaired project, and project diagnostics are not this
            // binding's.
            (
                Some(1),
                json!([
                    diagnostic(
                        runtime,
                        "casework.runtime.invalid-context-provider",
                        "/contextProviders/registry-other/resource"
                    ),
                    diagnostic(
                        runtime,
                        "casework.runtime.context-providers-mismatch",
                        "/contextProviders"
                    ),
                    diagnostic(
                        "CaseworkProject",
                        "casework.project.invalid",
                        "/reviewPolicies"
                    ),
                ]),
                BindingCheck::Accepted,
            ),
            // The loader refused the file elsewhere, so Casework never read
            // the binding.
            (
                Some(1),
                json!([diagnostic(runtime, "config.unknown-key", "/listener/port")]),
                BindingCheck::Unchecked,
            ),
            (
                Some(3),
                json!([diagnostic(
                    runtime,
                    "casework.runtime.unknown",
                    "/contextProviders/registry"
                )]),
                BindingCheck::Unchecked,
            ),
            (None, json!([]), BindingCheck::Unchecked),
        ] {
            let status = if code == Some(0) {
                "complete"
            } else {
                "domain-refusal"
            };
            assert_eq!(
                casework_binding_check(code, &report(status, diagnostics.clone()), "registry"),
                expected,
                "{code:?} {diagnostics}"
            );
        }
        let explain = json!({
            "apiVersion": "id.registrystack.org/formats/casework/report/v1alpha2",
            "kind": "CaseworkReport", "command": "explain", "status": "complete", "ok": true
        });
        assert_eq!(
            casework_binding_check(Some(0), &explain, "registry"),
            BindingCheck::Unchecked
        );
    }

    #[test]
    fn check_renders_the_casework_configuration_start_writes() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("run");
        super::super::private_directory(&root).unwrap();
        let terminate = AtomicBool::new(false);
        let mut input = breg_input(false);
        input.plan = serde_json::from_value(json!({
            "issuer": "https://issuer.example.invalid",
            "products": [
                {"product": "breg", "project": ".", "audience": "urn:example:registry"},
                {"product": "casework", "project": "casework", "audience": "urn:example:review"}
            ],
            "people": {"reviewer": {
                "subject": "reviewer", "client": "reviewer-client",
                "grants": {"casework": {"profile": "reviewer", "scopes": ["casework:review"]}}
            }},
            "journey": {"id": "read", "steps": [{
                "id": "read", "product": "casework", "as": "reviewer", "method": "GET",
                "path": "/v1/review-tasks", "expect": {"status": 200}
            }]}
        }))
        .unwrap();
        let identity = format!("dev-{}-casework", input.run_id);
        let runner = ProductRunner::new(Arc::new(input), &root, &terminate).unwrap();
        let urls = DatabaseUrls {
            runtime: "postgresql://runtime:password@127.0.0.1:5432/run".to_owned(),
            migration: "postgresql://migration:password@127.0.0.1:5432/run".to_owned(),
        };
        let package = root.join("casework-package");
        let path = runner
            .config(Product::Casework, "casework", "127.0.0.1:0", &package, urls)
            .unwrap();
        let written: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();

        let rendered = casework_config(
            &runner.input.plan,
            "casework",
            &root,
            &package,
            &identity,
            "127.0.0.1:0",
        );
        assert_eq!(written, rendered);
        assert_eq!(
            written["authentication"]["oidc"]["allowedClients"],
            json!(["reviewer-client"])
        );
        assert!(!written.to_string().contains("password"), "{written}");
    }

    #[test]
    fn messaging_config_uses_its_own_database_audience_and_workload_client() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("run");
        super::super::private_directory(&root).unwrap();
        let terminate = AtomicBool::new(false);
        let mut input = breg_input(false);
        input.breg_authority = None;
        input.plan = serde_json::from_value(json!({
            "issuer": "https://issuer.example.invalid",
            "products": [{
                "product": "messaging", "project": ".",
                "audience": "urn:example:messaging"
            }],
            "people": {"sender": {
                "subject": "sender", "client": "sender-client",
                "grants": {"messaging": {
                    "profile": "sender", "scopes": ["messaging:send"],
                    "claims": {"registry_actor_kind": "service"}
                }}
            }},
            "workloads": {"notices": {
                "product": "messaging", "default": true,
                "subject": "service", "client": "workload-client",
                "grant": {
                    "profile": "sender", "scopes": ["messaging:send"],
                    "claims": {"registry_actor_kind": "service"}
                }
            }},
            "journey": {"id": "send", "steps": [{
                "id": "send", "product": "messaging", "as": "sender",
                "method": "POST", "path": "/v1/messages", "body": {},
                "expect": {"status": 202}
            }]}
        }))
        .unwrap();
        input.messaging_clients = BTreeSet::from(["package-operator".to_owned()]);
        let runner = ProductRunner::new(Arc::new(input), &root, &terminate).unwrap();
        let urls = DatabaseUrls {
            runtime: "postgresql://runtime:password@127.0.0.1:5432/messaging".to_owned(),
            migration: "postgresql://migration:password@127.0.0.1:5432/messaging".to_owned(),
        };
        let path = runner
            .config(
                Product::Messaging,
                "messaging",
                "127.0.0.1:8107",
                &root.join("messaging-package"),
                urls,
            )
            .unwrap();
        let text = fs::read_to_string(path).unwrap();
        let written: Value = serde_json::from_str(&text).unwrap();

        assert_eq!(written["kind"], "MessagingRuntimeConfig");
        assert_eq!(
            written["authentication"]["oidc"]["audience"],
            "urn:example:messaging"
        );
        assert_eq!(
            written["authentication"]["oidc"]["allowedClients"],
            json!(["package-operator", "sender-client", "workload-client"])
        );
        assert_eq!(
            written["listener"]["tlsTermination"],
            "development-loopback"
        );
        assert_eq!(
            written["database"]["runtimeUrlRef"],
            "secret:file/messaging-runtime-url"
        );
        assert!(written.get("providers").is_none());
        assert!(!text.contains("password"), "{written}");
    }

    #[test]
    fn messaging_workloads_must_match_the_owning_profile_authority() {
        let report = json!({
            "apiVersion": "id.registrystack.org/formats/messaging/ctl-report/v1alpha1",
            "kind": "MessagingCtlReport", "command": "check",
            "status": "complete", "ok": true, "diagnostics": [],
            "accessProfiles": [{
                "id": "service-sender", "actsAs": "sender",
                "principalClaim": "sub", "requiredScopes": ["messaging:send"],
                "requesterClients": ["notice-service"], "actorKind": "service"
            }]
        });
        let profiles = messaging_report_profiles(&report).unwrap();
        let mut plan: Plan = serde_json::from_value(json!({
            "issuer": "https://issuer.example.invalid",
            "products": [{"product": "messaging", "project": ".", "audience": "urn:messaging"}],
            "people": {"sender": {
                "subject": "sender", "client": "notice-service",
                "grants": {"messaging": {
                    "profile": "service-sender", "scopes": ["messaging:send"],
                    "claims": {"registry_actor_kind": "service"}
                }}
            }},
            "workloads": {"notices": {
                "product": "messaging", "default": true,
                "subject": "service", "client": "notice-service",
                "grant": {
                    "profile": "service-sender", "scopes": ["messaging:send"],
                    "claims": {"registry_actor_kind": "service"}
                }
            }},
            "journey": {"id": "send", "steps": [{
                "id": "send", "product": "messaging", "as": "sender",
                "method": "POST", "path": "/v1/messages", "body": {},
                "expect": {"status": 202}
            }]}
        }))
        .unwrap();

        validate_messaging_grants(&plan, &profiles).unwrap();
        plan.workloads.get_mut("notices").unwrap().client = "other-service".to_owned();
        let error = validate_messaging_grants(&plan, &profiles)
            .unwrap_err()
            .to_string();
        assert!(error.contains("/workloads/notices/client"), "{error}");
    }

    #[test]
    fn messaging_reports_refuse_authority_values_the_owning_tool_cannot_emit() {
        let report = || {
            json!({
                "apiVersion": "id.registrystack.org/formats/messaging/ctl-report/v1alpha1",
                "kind": "MessagingCtlReport", "command": "check",
                "status": "complete", "ok": true, "diagnostics": [],
                "accessProfiles": [{
                    "id": "service-sender", "actsAs": "sender",
                    "principalClaim": "sub", "requiredScopes": ["messaging:send"],
                    "requesterClients": ["notice-service"], "actorKind": "service"
                }]
            })
        };

        let mut duplicate = report();
        duplicate["accessProfiles"][0]["requiredScopes"] =
            json!(["messaging:send", "messaging:send"]);
        assert!(messaging_report_profiles(&duplicate).is_err());

        let mut invalid = report();
        invalid["accessProfiles"][0]["actorKind"] = json!("robot");
        assert!(messaging_report_profiles(&invalid).is_err());

        let mut missing = report();
        missing["accessProfiles"][0]["actsAs"] = Value::Null;
        assert!(messaging_report_profiles(&missing).is_err());
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
        let error = run_logged_tool_direct(
            Path::new("/bin/sh"),
            &["-c".as_ref(), "echo boom >&2; exit 3".as_ref()],
            root,
            ("breg", "test"),
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
        run_logged_tool_direct(
            Path::new("/bin/sh"),
            &["-c".as_ref(), "echo fine >&2".as_ref()],
            scratch.path(),
            ("breg", "test"),
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
                {"product": "breg", "pid": 4242, "pgid": 4242, "started": null},
                {"product": "casework", "pid": 4343, "pgid": 4343, "started": null}
            ])
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_live_process_is_recorded_with_its_start_time() {
        let scratch = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        write_processes(scratch.path(), &[(Product::Breg, child.id())]).unwrap();
        let recorded: Value =
            serde_json::from_slice(&fs::read(scratch.path().join("processes.json")).unwrap())
                .unwrap();
        let started = recorded[0]["started"].as_str().map(str::to_owned);
        assert!(started.is_some(), "{recorded}");
        assert_eq!(
            started,
            crate::project_dev::recovery::started_at(child.id())
        );
        child.kill().unwrap();
        child.wait().unwrap();
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
        assert!(
            error.ends_with("Next: Set profile to an access profile defined by the BReg project."),
            "{error}"
        );
        assert!(!error.contains("directory-edtor"), "{error}");
        let valid = BTreeMap::from([("editor".to_owned(), breg_person("directory-editor"))]);
        check_breg_grants(&registry, &valid).unwrap();
    }

    #[test]
    fn a_breg_workload_naming_an_unknown_profile_is_refused_at_its_pointer() {
        let registry = minimal_registry(str::to_owned);
        let workload = |profile: &str| {
            serde_json::from_value(json!({
                "product": "breg", "default": true,
                "subject": "service", "client": "service",
                "grant": {"profile": profile, "scopes": []}
            }))
            .unwrap()
        };
        let workloads = BTreeMap::from([("registry".to_owned(), workload("directory-edtor"))]);
        let error = check_breg_workloads(&registry, &workloads)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("/workloads/registry/grant/profile"),
            "{error}"
        );
        assert!(!error.contains("directory-edtor"), "{error}");
        check_breg_workloads(
            &registry,
            &BTreeMap::from([("registry".to_owned(), workload("directory-editor"))]),
        )
        .unwrap();
    }

    #[test]
    fn a_breg_grant_may_name_a_profile_with_only_proposal_permissions() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance/reviewed-evidence-journey/registry");
        let scratch = tempfile::tempdir().unwrap();
        let project = scratch.path().join("project");
        copy_project(&source, &project).unwrap();
        let registry = crate::compile(&project, crate::ProfileArg::Production, "project-dev-test")
            .unwrap_or_else(|_| panic!("the reviewed evidence project must compile"));
        let people = BTreeMap::from([("applier".to_owned(), breg_person("applier"))]);
        check_breg_grants(&registry, &people).unwrap();
    }

    fn encrypt_contact_email(source: &str) -> String {
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
    }

    #[test]
    fn the_compiled_project_decides_whether_a_run_encrypts_fields() {
        assert!(breg_encrypts_fields(&minimal_registry(
            encrypt_contact_email
        )));
        assert!(!breg_encrypts_fields(&minimal_registry(str::to_owned)));
    }

    fn breg_input(encrypts_fields: bool) -> RunInput {
        RunInput {
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
            project: PathBuf::from("/tmp/project"),
            plan: serde_json::from_value(json!({
                "issuer": "https://issuer.example.invalid",
                "products": [{"product": "breg", "project": ".", "audience": "registry"}],
                "people": {"reader": {
                    "subject": "reader", "client": "reader-client",
                    "grants": {"breg": {"profile": "reader", "scopes": []}}
                }},
                "journey": {"id": "read", "steps": [{
                    "id": "read", "product": "breg", "as": "reader", "method": "GET",
                    "path": "/v1/records", "expect": {"status": 200}
                }]}
            }))
            .unwrap(),
            ttl_seconds: 300,
            schema_people: Vec::new(),
            breg_authority: Some(BregAuthority {
                principal: "sub".to_owned(),
                purpose: false,
                requires_postgis: false,
                encrypts_fields,
                named_clients: BTreeSet::new(),
            }),
            casework_principals: BTreeMap::new(),
            messaging_clients: BTreeSet::new(),
            binaries: BTreeMap::new(),
        }
    }

    fn breg_config(runner: &ProductRunner<'_>, root: &Path, name: &str) -> (Value, String) {
        let urls = DatabaseUrls {
            runtime: "postgresql://runtime:password@127.0.0.1:5432/run".to_owned(),
            migration: "postgresql://migration:password@127.0.0.1:5432/run".to_owned(),
        };
        let path = runner
            .config(
                Product::Breg,
                name,
                "127.0.0.1:0",
                &root.join("package"),
                urls,
            )
            .unwrap();
        let text = fs::read_to_string(path).unwrap();
        (serde_json::from_str(&text).unwrap(), text)
    }

    #[test]
    fn an_encrypting_run_configures_local_file_custody_with_an_owner_only_run_key() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("run");
        super::super::private_directory(&root).unwrap();
        let terminate = AtomicBool::new(false);
        let runner = ProductRunner::new(Arc::new(breg_input(true)), &root, &terminate).unwrap();

        runner.write_field_key().unwrap();
        let key = root.join(FIELD_KEY);
        assert_eq!(field_key_file(&root), Some(key.clone()));
        let refused = runner.write_field_key().unwrap_err();
        assert!(refused.is::<Operational>(), "{refused:#}");
        assert!(
            refused
                .to_string()
                .ends_with("run directory: a key file already exists at that path"),
            "{refused:#}"
        );
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let encoded = fs::read_to_string(&key).unwrap();
        assert_eq!(STANDARD.decode(encoded.trim()).unwrap().len(), 32);

        // The rehearsal and the served database read the same run key, by
        // reference only; local-file custody requires local initialization.
        for name in ["breg-test", "breg"] {
            let (config, text) = breg_config(&runner, &root, name);
            assert_eq!(
                config["fieldEncryption"],
                json!({"provider": {"type": "local-file", "dekRef": format!("secret:file/{FIELD_KEY}")}}),
                "{name}"
            );
            assert_eq!(config["secretProviders"]["file"]["root"], json!(root));
            assert_eq!(config["identity"]["environment"], "local");
            assert_eq!(
                config["identity"]["databaseInitializationEnvironment"],
                "local"
            );
            assert!(!text.contains(encoded.trim()), "{name}");
        }

        // Each run draws its own key.
        let other = scratch.path().join("other");
        super::super::private_directory(&other).unwrap();
        let second = ProductRunner::new(Arc::new(breg_input(true)), &other, &terminate).unwrap();
        second.write_field_key().unwrap();
        assert_ne!(fs::read_to_string(other.join(FIELD_KEY)).unwrap(), encoded);
    }

    #[test]
    fn an_unavailable_inspection_is_operational_and_names_its_cause() {
        let class =
            |error: &anyhow::Error| super::super::error_report(error).0["error"]["class"].clone();
        let unavailable = anyhow::Error::new(InspectionUnavailable::new(
            "products[0]",
            "The Casework project cannot be inspected.",
            "Install the tools.",
        ));
        assert_eq!(class(&unavailable), "operational");

        let terminate = AtomicBool::new(false);
        let missing = Path::new("/nonexistent/caseworkctl");
        let error = explain_casework_facts(missing, Path::new("."), &terminate).unwrap_err();
        let failed = inspection_failed(
            "products[0]",
            "inspect the Casework project",
            error,
            &terminate,
        );
        assert_eq!(class(&failed), "operational");
        let reason = failed
            .downcast_ref::<InspectionUnavailable>()
            .expect("an unavailable inspection")
            .reason();
        assert!(
            reason.contains(
                "could not inspect the Casework project: cannot start caseworkctl explain"
            ),
            "{reason}"
        );
    }

    #[test]
    fn an_interrupted_inspection_stays_the_operators_request() {
        let class =
            |error: &anyhow::Error| super::super::error_report(error).0["error"]["class"].clone();
        let terminate = AtomicBool::new(true);
        let interrupted = anyhow::anyhow!("development product inspection was interrupted");
        let failed = inspection_failed(
            "products[0]",
            "inspect the Casework project",
            interrupted,
            &terminate,
        );
        assert!(!failed.is::<InspectionUnavailable>());
        assert_eq!(class(&failed), "domain");
        assert_eq!(
            failed.to_string(),
            "development product inspection was interrupted"
        );
    }

    #[test]
    fn missed_readiness_and_start_deadlines_are_operational() {
        let class =
            |error: &anyhow::Error| super::super::error_report(error).0["error"]["class"].clone();
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("run");
        super::super::private_directory(&root).unwrap();
        let terminate = AtomicBool::new(false);
        let mut runner =
            ProductRunner::new(Arc::new(breg_input(false)), &root, &terminate).unwrap();
        let unused = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let not_ready = runner
            .ready(
                Product::Breg,
                &format!("http://127.0.0.1:{unused}"),
                Duration::ZERO,
            )
            .unwrap_err();
        assert_eq!(class(&not_ready), "operational", "{not_ready:#}");
        assert!(
            not_ready
                .to_string()
                .starts_with("breg did not become ready"),
            "{not_ready:#}"
        );

        runner.deadline = Instant::now();
        let late = runner.ensure_active().unwrap_err();
        assert_eq!(class(&late), "operational", "{late:#}");
        assert_eq!(
            late.to_string(),
            "development run did not start within five minutes"
        );

        // A stop requested during startup stays a refusal.
        terminate.store(true, Ordering::Relaxed);
        let stopped = runner.ensure_active().unwrap_err();
        assert_eq!(class(&stopped), "domain", "{stopped:#}");
    }

    #[test]
    fn a_run_without_encrypted_fields_writes_no_key_and_no_provider() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("run");
        super::super::private_directory(&root).unwrap();
        let terminate = AtomicBool::new(false);
        let runner = ProductRunner::new(Arc::new(breg_input(false)), &root, &terminate).unwrap();
        runner.write_field_key().unwrap();
        assert_eq!(field_key_file(&root), None);
        let (config, _) = breg_config(&runner, &root, "breg");
        assert!(config.get("fieldEncryption").is_none(), "{config}");
        assert_eq!(config["identity"]["environment"], "local");
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
        assert_eq!(
            guard::stop_direct_child(&mut child).unwrap().code(),
            Some(7)
        );
    }

    fn wait_for_leader(child: &Child) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !guard::direct_child_exited(child).unwrap() {
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
        let pid = guard::direct_child_pid(&child).unwrap();
        assert_eq!(rustix::process::getpgid(Some(pid)).unwrap(), pid);
        let mut pipe = BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        pipe.read_line(&mut ready).unwrap();
        assert_eq!(ready, "ready\n");
        if leader_exits {
            wait_for_leader(&child);
        }
        guard::stop_direct_child(&mut child).unwrap();

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
