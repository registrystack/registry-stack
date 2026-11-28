// SPDX-License-Identifier: Apache-2.0
//! Activate ordinary packages and serve them on the run's private bindings.

use anyhow::{bail, ensure, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::{Read, Seek, SeekFrom},
    net::{Ipv4Addr, TcpListener},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
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
    bindings::{Bindings, BregReviewAuthority, RunIssuerBinding, RuntimeBindings},
    browser::BrowserClient,
    clock,
    database::{Database, DatabaseUrls},
    docker::Docker,
    explain::{breg_facts, BregFacts, InvalidBregProject},
    guard,
    issuer::Issuer,
    operational,
    plan::{self, ApplicationPlan, Plan, Product},
    private_directory,
    sinks::GatewayServer,
    stopping, write_private, BregAuthority, RunInput, MAILPIT_MARKER, POLL,
};

#[path = "evidence.rs"]
mod evidence;
#[path = "messaging.rs"]
mod messaging;

/// Makes the run's Evidence package and packaging output writable again so the run directory can be removed.
pub(super) fn unlock_package(root: &Path) -> Result<()> {
    evidence::unlock_package(root)
}

/// The run's development field-encryption data key, inside the owner-only run
/// directory and removed with it.
pub(super) const FIELD_KEY: &str = "field-key";

/// The largest tool report the runner reads or retains.
const MAX_TOOL_REPORT: u64 = 4 * 1024 * 1024;
/// The `apiVersion` of every `caseworkctl` JSON report.
const CASEWORK_REPORT_API_VERSION: &str = "id.registrystack.org/formats/casework/report/v1alpha2";

/// The format of the file `bregctl test --credentials` reads. The published
/// schema is `products/breg/generated/tools/schema-test-credentials.v1.schema.json`.
const SCHEMA_CREDENTIALS_API_VERSION: &str =
    "id.registrystack.org/formats/breg/schema-test-credentials/v1";
const SCHEMA_CREDENTIALS_KIND: &str = "BRegSchemaTestCredentials";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SchemaCredentials<'a> {
    api_version: &'static str,
    kind: &'static str,
    bindings: Vec<SchemaCredentialBinding<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SchemaCredentialBinding<'a> {
    journey_id: &'a str,
    step_id: &'a str,
    credential: SchemaCredential,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SchemaCredential {
    #[serde(rename = "type")]
    kind: &'static str,
    token_ref: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RuntimeKind {
    Product(Product),
    Application,
}

impl RuntimeKind {
    fn name(self) -> &'static str {
        match self {
            Self::Product(product) => product.name(),
            Self::Application => "application",
        }
    }
}

/// The refusal for a product that needs the run's database when the run has none.
const NEEDS_DATABASE: &str = "the product needs a database but the run has none";

/// How long a started product has to answer `/ready`.
const READINESS_WAIT: Duration = Duration::from_secs(30);

/// A locally built application process. Its configuration and environment are
/// prepared by the caller before the run starts a guarded child.
pub(super) struct ApplicationLaunch {
    pub(super) program: PathBuf,
    pub(super) arguments: Vec<OsString>,
    pub(super) workdir: PathBuf,
    pub(super) environment: BTreeMap<String, String>,
    pub(super) reservation: TcpListener,
    pub(super) health_path: String,
}

pub(super) struct PreparedApplication {
    pub(super) launch: ApplicationLaunch,
    pub(super) client: BrowserClient,
}

fn application_run_input(
    input: &RunInput,
    urls: &BTreeMap<Product, String>,
    origin: &str,
    port: u16,
    client_secret_file: &Path,
    recovery_file: Option<&Path>,
) -> Value {
    let plan = input
        .plan
        .application
        .as_ref()
        .expect("declared application");
    let mut oidc = json!({
        "issuer": input.plan.issuer,
        "clientSecretFile": client_secret_file,
        "accessTokenSigningAlgorithm": "ES256",
    });
    let mut run = json!({
        "schema": plan.config_schema,
        "origin": origin,
        "port": port,
        "insecureLocal": true,
        "cookieNamespace": input.run_id,
        "oidc": oidc,
        "breg": {
            "baseUrl": urls[&Product::Breg],
            "audience": input.plan.product(Product::Breg).audience,
        }
    });
    if let Some(base_url) = urls.get(&Product::Casework) {
        oidc["recoveryKeyFile"] = json!(recovery_file.expect("Casework recovery key"));
        oidc["separateResourceGrants"] = json!(true);
        run["oidc"] = oidc;
        run["casework"] = json!({
            "baseUrl": base_url,
            "audience": input.plan.product(Product::Casework).audience,
        });
        if let Some(roles) = &plan.casework_source_credential_roles {
            run["casework"]["sourceCredentialRoles"] = json!(roles);
        }
    }
    run
}

pub(super) fn application_file(root: &Path, relative: &Path) -> Result<PathBuf> {
    let root = root
        .canonicalize()
        .context("built application root is missing")?;
    let path = root
        .join(relative)
        .canonicalize()
        .context("built application file is missing")?;
    ensure!(
        path.starts_with(root) && path.is_file(),
        "built application file must be inside its root"
    );
    Ok(path)
}

/// The application's Node floor. A newer Node runs with a warning, because the
/// application is built and tested against this major version.
const NODE_MAJOR_FLOOR: u32 = 24;

/// What the application preflight observed about the toolchain.
struct ApplicationPreflight {
    node: PathBuf,
    warnings: Vec<String>,
}

pub(super) fn preflight_application(root: &Path, plan: &ApplicationPlan) -> Result<PathBuf> {
    let preflight = preflight_application_with(root, plan, || {
        std::env::var_os("PATH")
            .into_iter()
            .flat_map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
            .map(|directory| directory.join("node"))
            .find(|path| path.is_file())
            .context("Node 24 or newer is required to start the declared application")?
            .canonicalize()
            .map_err(Into::into)
    })?;
    for warning in &preflight.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(preflight.node)
}

fn preflight_application_with(
    root: &Path,
    plan: &ApplicationPlan,
    node: impl FnOnce() -> Result<PathBuf>,
) -> Result<ApplicationPreflight> {
    for relative in [&plan.entry, &plan.prepare, &plan.checker] {
        application_file(root, relative)?;
    }
    let node = node()?;
    let node_version = bounded_version(&node, None)?;
    let major = node_version
        .strip_prefix('v')
        .and_then(|version| version.split('.').next())
        .and_then(|major| major.parse::<u32>().ok())
        .with_context(|| format!("cannot read the Node version from {node_version:?}"))?;
    ensure!(
        major >= NODE_MAJOR_FLOOR,
        "declared application requires Node {NODE_MAJOR_FLOOR} or newer; found {node_version}"
    );
    let mut warnings = Vec::new();
    if major > NODE_MAJOR_FLOOR {
        warnings.push(format!(
            "the declared application is tested with Node {NODE_MAJOR_FLOOR}; found {node_version}"
        ));
    }
    let prepare = application_file(root, &plan.prepare)?;
    let prepare_version = bounded_version(&node, Some(&prepare))?;
    if prepare_version != plan.prepare_version {
        warnings.push(format!(
            "the application configuration command reports {prepare_version:?}; /application/prepareVersion in dev.yaml names {:?}",
            plan.prepare_version
        ));
    }
    Ok(ApplicationPreflight { node, warnings })
}

#[cfg(test)]
fn preflight_application_with_node(
    root: &Path,
    plan: &ApplicationPlan,
    node: &Path,
) -> Result<ApplicationPreflight> {
    preflight_application_with(root, plan, || Ok(node.canonicalize()?))
}

fn bounded_version(node: &Path, script: Option<&Path>) -> Result<String> {
    let mut command = Command::new(node);
    if let Some(script) = script {
        command.arg(script);
    }
    command
        .arg("--version")
        .env(super::POSTURE_ENV, super::DEVELOPMENT)
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .context("cannot inspect application toolchain")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(
                status.success(),
                "application toolchain version command failed"
            );
            let mut output = Vec::new();
            child
                .stdout
                .take()
                .context("missing version output")?
                .take(256)
                .read_to_end(&mut output)?;
            let line = std::str::from_utf8(&output)?.trim_end_matches('\n');
            ensure!(
                !line.contains('\n') && !line.contains('\r'),
                "application version output must be one line"
            );
            return Ok(line.to_owned());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            bail!("application toolchain version command timed out");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

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
    children: Vec<(RuntimeKind, guard::Child)>,
    bindings: Option<RuntimeBindings>,
    /// The run issuer, kept so Evidence's key set can serve its public keys.
    issuer: Option<Arc<Issuer>>,
    /// The run issuer's reserved listener, held for the key set server of an
    /// Evidence run until Evidence activates.
    issuer_listener: Option<TcpListener>,
    /// The loopback key set server Evidence's target names, stopped with the run.
    jwks: Option<evidence::JwksServer>,
    coordinator_issuer: Option<evidence::JwksServer>,
    /// The mock gateway Messaging's `http` providers send to, stopped with the
    /// run.
    gateway: Option<GatewayServer>,
    hook_sink: Option<GatewayServer>,
    /// Where each Messaging provider's sent messages can be read, by provider
    /// ID.
    sinks: BTreeMap<String, Value>,
    /// The `providers` member of Messaging's runtime configuration, once the
    /// run has started the sinks the providers send to.
    messaging_providers: Option<Value>,
    /// The runtime configuration the run wrote for each product.
    runtime_configs: BTreeMap<Product, PathBuf>,
    created_kept_keys: RefCell<Vec<PathBuf>>,
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
            issuer: None,
            issuer_listener: None,
            jwks: None,
            coordinator_issuer: None,
            gateway: None,
            hook_sink: None,
            sinks: BTreeMap::new(),
            messaging_providers: None,
            runtime_configs: BTreeMap::new(),
            created_kept_keys: RefCell::default(),
        })
    }

    pub(super) fn created_kept_keys(&self) -> std::cell::Ref<'_, Vec<PathBuf>> {
        self.created_kept_keys.borrow()
    }

    /// Reserve no authority for a new key until its file and its marker are
    /// both in owner-only project state, under the supervisor's project lock.
    fn kept_key(
        &self,
        state: &Path,
        name: &str,
        create: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let path = state.join(name);
        let marker = state.join(format!("kept-key-{name}"));
        let recorded = super::read_private(&marker)?.is_some();
        let existing = super::read_private(&path)?.map(zeroize::Zeroizing::new);
        let created = existing.is_none();
        let bytes = match existing {
            Some(bytes) => bytes,
            None => {
                ensure!(
                    !recorded,
                    "Retained key {} is missing. Start with --clean",
                    path.display()
                );
                create(&path)?;
                super::read_private(&path)?
                    .map(zeroize::Zeroizing::new)
                    .context("key generation produced no key")?
            }
        };
        if !recorded {
            write_private(&marker, b"")?;
        }
        if created {
            self.created_kept_keys.borrow_mut().push(path);
        }
        Ok(bytes)
    }

    /// Hands over the run issuer's listener to serve Evidence's key set.
    pub(super) fn hold_issuer_listener(&mut self, listener: TcpListener) {
        self.issuer_listener = Some(listener);
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
            if entry.product == Product::Evidence {
                // Evidence checks a project against a target. The project's
                // `local-target.yaml` names its development connections.
                let target = project.join("local-target.yaml");
                self.tool(
                    entry.product,
                    "check",
                    &[project.as_os_str(), "--target".as_ref(), target.as_os_str()],
                )?;
                continue;
            }
            if matches!(
                entry.product,
                Product::Messaging
                    | Product::Documents
                    | Product::Discovery
                    | Product::Coordinator
                    | Product::Render
            ) {
                self.tool(
                    entry.product,
                    "check",
                    &[
                        if entry.product == Product::Render {
                            "--bundle"
                        } else {
                            "--project"
                        }
                        .as_ref(),
                        project.as_os_str(),
                    ],
                )?;
                continue;
            }
            self.tool(entry.product, "check", &[project.as_os_str()])?;
        }
        Ok(())
    }

    /// Where each Messaging provider's sent messages can be read, by provider
    /// ID. It is empty unless the run started Messaging.
    pub(super) fn sinks(&self) -> Value {
        json!(self.sinks)
    }

    /// The absolute path of the runtime configuration the run wrote for each
    /// started product.
    pub(super) fn runtime_configs(&self) -> Value {
        json!(self.runtime_configs)
    }

    /// Starts every product in the plan. `docker` is the run's Docker
    /// connection when it has one, and is connected here when a sink needs it.
    pub(super) fn start(
        &mut self,
        mut database: Option<&mut Database>,
        docker: &mut Option<Docker>,
        issuer: Arc<Issuer>,
    ) -> Result<BTreeMap<Product, String>> {
        self.issuer = Some(issuer.clone());
        if self.input.plan.jwks_uri().is_none()
            && self
                .input
                .plan
                .products
                .iter()
                .any(|entry| entry.product == Product::Coordinator)
        {
            let coordinator =
                product_root(&self.input.project, &self.input.plan, Product::Coordinator)?
                    .context("missing Coordinator project")?;
            let runtime = authored_document(&coordinator.root.join("runtime.yaml"))?;
            let state = needs_stable_issuer(&runtime, self.input.plan.jwks_uri())
                .then(|| self.product_state("coordinator"))
                .flatten();
            let listener = coordinator_issuer_listener(state.as_deref())?;
            self.coordinator_issuer = Some(evidence::JwksServer::start(
                listener,
                &issuer.public_jwks(),
            )?);
        }
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
                    let (config, package) = self.activate_breg(
                        database.as_deref_mut().context(NEEDS_DATABASE)?,
                        &issuer,
                        &project,
                        bind,
                    )?;
                    breg_package = Some(package);
                    config
                }
                Product::Casework => self.activate_casework(
                    database.as_deref_mut().context(NEEDS_DATABASE)?,
                    &project,
                    bind,
                    breg_package.as_deref(),
                )?,
                Product::Evidence => self.activate_evidence(&project, bind)?,
                Product::Messaging => self.activate_messaging(
                    database.as_deref_mut().context(NEEDS_DATABASE)?,
                    docker,
                    &project,
                    bind,
                )?,
                other => {
                    self.activate_additional(other, database.as_deref_mut(), &project, bind)?
                }
            };
            let binaries = &self.input.binaries[&product];
            let mut command = guard::Command::new(
                self.root,
                &format!("runtime-{}", product.name()),
                &binaries.runtime,
            )
            .map_err(operational)?;
            if matches!(
                product,
                Product::Evidence | Product::Adapter | Product::Render
            ) {
                command.arg("serve");
            }
            command.arg("--runtime-config").arg(&config);
            self.runtime_configs.insert(product, config);
            if product == Product::Adapter {
                command.arg("--project").arg(&project);
            }
            if matches!(
                product,
                Product::Casework | Product::Messaging | Product::Scheduling | Product::Documents
            ) {
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
            self.children.push((RuntimeKind::Product(product), child));
            self.record_processes()?;
            let ready = if product == Product::Scheduling {
                "/readyz"
            } else {
                "/ready"
            };
            self.ready(RuntimeKind::Product(product), url, ready, READINESS_WAIT)?;
        }
        Ok(urls)
    }

    pub(super) fn start_application(&mut self, launch: ApplicationLaunch) -> Result<String> {
        self.ensure_active()?;
        ensure!(
            launch.program.is_absolute() && launch.program.is_file(),
            "application program must be a built local file"
        );
        ensure!(
            launch.workdir.is_absolute() && launch.workdir.is_dir(),
            "application working directory is unavailable"
        );
        ensure!(
            valid_health_path(&launch.health_path),
            "application health path must be a local absolute path"
        );
        let origin = format!("http://{}", launch.reservation.local_addr()?);
        let mut command = guard::Command::isolated(
            self.root,
            "runtime-application",
            &launch.program,
            &launch.workdir,
            &launch.environment,
        )?;
        command.args(&launch.arguments);
        let log = open_log(self.root, "application-runtime")?;
        command.stdout(log.try_clone()?).stderr(log);
        drop(launch.reservation);
        let child = command
            .spawn()
            .context("cannot start application")
            .map_err(operational)?;
        self.children.push((RuntimeKind::Application, child));
        self.record_processes()?;
        self.ready(
            RuntimeKind::Application,
            &origin,
            &launch.health_path,
            READINESS_WAIT,
        )?;
        Ok(origin)
    }

    pub(super) fn prepare_application(
        &self,
        urls: &BTreeMap<Product, String>,
    ) -> Result<PreparedApplication> {
        self.ensure_active()?;
        let plan = self
            .input
            .plan
            .application
            .as_ref()
            .context("application is not declared")?;
        let root = self
            .input
            .application_root
            .as_ref()
            .context("built application root is missing")?;
        let node = self
            .input
            .application_node
            .as_ref()
            .context("application Node executable is missing")?;
        let entry = application_file(root, &plan.entry)?;
        let prepare = application_file(root, &plan.prepare)?;
        let checker = application_file(root, &plan.checker)?;
        let deployment = self.input.project.join(&plan.deployment).canonicalize()?;
        ensure!(
            deployment.starts_with(&self.input.project) && deployment.is_file(),
            "application deployment file is unavailable"
        );
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .context("reserve application loopback listener")
            .map_err(operational)?;
        let address = reservation.local_addr()?;
        let origin = format!("http://{address}");
        let secret = random_secret()?;
        let client_secret_file = self.root.join("application-client-secret");
        write_private(&client_secret_file, secret.as_bytes())?;
        let recovery_file = if urls.contains_key(&Product::Casework) {
            let recovery_key = random_secret()?;
            let recovery_file = self.root.join("application-recovery-key");
            write_private(&recovery_file, recovery_key.as_bytes())?;
            Some(recovery_file)
        } else {
            None
        };
        let run = application_run_input(
            &self.input,
            urls,
            &origin,
            address.port(),
            &client_secret_file,
            recovery_file.as_deref(),
        );
        let run_file = self.root.join("application-run.json");
        let config_file = self.root.join("application-host.json");
        write_private(&run_file, &serde_json::to_vec(&run)?)?;
        self.application_tool(
            "application-prepare",
            node,
            root,
            &prepare,
            &[
                "--deployment".as_ref(),
                deployment.as_os_str(),
                "--run".as_ref(),
                run_file.as_os_str(),
                "--out".as_ref(),
                config_file.as_os_str(),
            ],
        )?;
        let metadata = fs::symlink_metadata(&config_file)
            .context("application configuration was not written")?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= 1024 * 1024,
            "application configuration must be a bounded regular file"
        );
        self.application_tool(
            "application-check",
            node,
            root,
            &checker,
            &[config_file.as_os_str()],
        )?;
        let mut environment = BTreeMap::new();
        environment.insert(
            plan.config_environment.clone(),
            config_file.to_string_lossy().into_owned(),
        );
        Ok(PreparedApplication {
            launch: ApplicationLaunch {
                program: node.clone(),
                arguments: vec![entry.into_os_string()],
                workdir: root.clone(),
                environment,
                reservation,
                health_path: plan.health_path.clone(),
            },
            client: BrowserClient {
                id: plan.client.clone(),
                secret,
                redirect_uri: format!("{origin}{}", plan.callback_path),
            },
        })
    }

    fn application_tool(
        &self,
        name: &str,
        node: &Path,
        root: &Path,
        entry: &Path,
        arguments: &[&std::ffi::OsStr],
    ) -> Result<()> {
        let environment =
            BTreeMap::from([(super::POSTURE_ENV.to_owned(), super::DEVELOPMENT.to_owned())]);
        let mut command = guard::Command::isolated(self.root, name, node, root, &environment)?;
        command.arg(entry).args(arguments);
        let log = open_log(self.root, name)?;
        command.stdout(log.try_clone()?).stderr(log);
        let mut child = command
            .spawn()
            .with_context(|| format!("cannot start {name}"))
            .map_err(operational)?;
        let status = wait_for_guarded_tool(&mut child, || self.ensure_active())?;
        ensure!(
            status.success(),
            "{name} refused the declared application; inspect the owner-only run log"
        );
        Ok(())
    }

    fn activate_breg(
        &mut self,
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
        self.prepare_breg_hooks(project)?;
        let urls = database
            .provision("breg", true, requires_postgis)
            .map_err(operational)?;
        let build = self.root.join("breg-build");
        let candidate = build.join("package");
        let baseline = if let Some(state) = self.product_state("breg") {
            // Status validates the runtime file before it reads the ledger.
            let probe = self.root.join("breg-status-package");
            private_directory(&probe)?;
            let config = self.config(Product::Breg, "breg", bind, &probe, urls.clone())?;
            self.breg_baseline(&config, &state)?
        } else {
            None
        };
        let mut retained_changes = Vec::new();
        if let Some(baseline) = &baseline {
            let (status, diff) = self.breg_report(
                "diff",
                &[
                    project.as_os_str(),
                    "--package".as_ref(),
                    baseline.as_os_str(),
                ],
            )?;
            ensure!(
                status.success(),
                "bregctl diff refused the retained package or project: {}. Start with --clean",
                report_codes(serde_json::to_vec(&diff)?.as_slice())?
            );
            if diff["changes"].as_array().is_some_and(Vec::is_empty) {
                let config = self.config(Product::Breg, "breg", bind, baseline, urls)?;
                self.tool(
                    Product::Breg,
                    "verify",
                    &["--runtime-config".as_ref(), config.as_os_str()],
                )?;
                return Ok((config, baseline.clone()));
            }
            let change_count = diff["changes"].as_array().map_or(0, Vec::len);
            retained_changes.extend(
                diff["changes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|item| {
                        let change = &item["change"];
                        let code = change["code"].as_str()?;
                        let target = &change["target"];
                        let member = target["memberId"]
                            .as_str()
                            .or(target["recordTypeId"].as_str());
                        Some(member.map_or_else(
                            || code.to_owned(),
                            |member| format!("{code} at {member}"),
                        ))
                    })
                    .take(6),
            );
            let remaining = change_count.saturating_sub(retained_changes.len());
            if remaining > 0 {
                retained_changes.push(format!("{remaining} more"));
            }
        }
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
        let mut test_args = vec![
            project.as_os_str(),
            "--runtime-config".as_ref(),
            config.as_os_str(),
            "--credentials".as_ref(),
            credentials.as_os_str(),
            "--output".as_ref(),
            receipt.as_os_str(),
        ];
        let mut package_args = breg_package_arguments(project, &receipt, &build).to_vec();
        if let Some(baseline) = &baseline {
            for args in [&mut test_args, &mut package_args] {
                args.extend(["--baseline-package".as_ref(), baseline.as_os_str()]);
            }
        }
        let retained_refusal =
            |error| retained_breg_refusal(error, baseline.is_some(), &retained_changes);
        self.tool(Product::Breg, "test", &test_args)
            .map_err(retained_refusal)?;
        self.tool(Product::Breg, "package", &package_args)
            .map_err(retained_refusal)?;
        let package = if let Some(state) = self.product_state("breg") {
            let sums = plan::read(&candidate.join("SHA256SUMS"), 4 * 1024 * 1024)?;
            let digest = registry_platform_config::sha256_uri(&sums);
            let retained = state.join(format!("breg-package-{}", &digest["sha256:".len()..]));
            if !retained.exists() {
                fs::rename(&candidate, &retained)
                    .context("cannot retain the verified BReg package")?;
            }
            retained
        } else {
            candidate
        };
        let config = self.config(
            Product::Breg,
            "breg",
            bind,
            baseline.as_deref().unwrap_or(&package),
            urls.clone(),
        )?;
        let mut apply = vec![
            "--runtime-config".as_ref(),
            config.as_os_str(),
            "--package".as_ref(),
            package.as_os_str(),
        ];
        if baseline.is_none() {
            apply.push("--initial".as_ref());
        }
        self.tool(Product::Breg, "apply", &apply)
            .map_err(retained_refusal)?;
        let config = self.config(Product::Breg, "breg", bind, &package, urls)?;
        self.tool(
            Product::Breg,
            "verify",
            &["--runtime-config".as_ref(), config.as_os_str()],
        )?;
        Ok((config, package))
    }

    fn breg_report(&self, stage: &str, args: &[&std::ffi::OsStr]) -> Result<(ExitStatus, Value)> {
        tool_report(
            &self.input.binaries[&Product::Breg].tool,
            "bregctl",
            stage,
            args,
            self.terminate,
        )
    }

    fn breg_baseline(&self, config: &Path, state: &Path) -> Result<Option<PathBuf>> {
        let (status, report) =
            self.breg_report("status", &["--runtime-config".as_ref(), config.as_os_str()])?;
        if !status.success() {
            let codes = report_codes(serde_json::to_vec(&report)?.as_slice())?;
            ensure!(
                only_refusal(&report, "status.database.uninitialized"),
                "bregctl status refused the retained database: {codes}. Start with --clean"
            );
            return Ok(None);
        }
        let digest = report["activePackageDigest"]
            .as_str()
            .filter(|digest| registry_platform_config::is_sha256_label(digest))
            .context("bregctl status did not report the active package digest")?;
        let package = state.join(format!("breg-package-{}", &digest["sha256:".len()..]));
        ensure!(
            package.is_dir(),
            "the active BReg package is missing at {}. Start with --clean",
            package.display()
        );
        Ok(Some(package))
    }

    /// Draw the run's own data key when the project encrypts fields. `bregctl
    /// field-encryption keygen` creates the file owner-only from the platform
    /// random source; the key is read only by the runtime through its
    /// `secret:file` reference.
    fn write_field_key(&self) -> Result<()> {
        if !self.encrypts_fields() {
            return Ok(());
        }
        let generate = |path: &Path| {
            self.tool(
                Product::Breg,
                "field-encryption",
                &["keygen".as_ref(), "--output".as_ref(), path.as_os_str()],
            )
        };
        let key = self.root.join(FIELD_KEY);
        if let Some(state) = self.input.project_state(self.root) {
            let bytes = self.kept_key(&state, FIELD_KEY, generate)?;
            write_private(&key, &bytes)?;
        } else if super::read_private(&key)?.is_none() {
            generate(&key)?;
        }
        Ok(())
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
            let token = if self.input.plan.jwks_uri().is_some() {
                let path = self.input.plan.external_breg.as_ref()
                    .and_then(|external| external.schema_test_headers.get(&binding.person))
                    .context("external BReg rehearsals need an owner-only schema test header for each person")?;
                crate::external_breg::ExternalBreg::bearer(&self.input.project, path)?
            } else {
                issuer.token(
                    &self.input,
                    &self.input.plan.people[&binding.person],
                    Product::Breg,
                    clock()? + 300,
                )?
            };
            let filename = format!("breg-schema-token-{index}");
            write_private(&self.root.join(&filename), token.as_bytes())?;
            bindings.push(SchemaCredentialBinding {
                journey_id: &binding.journey,
                step_id: &binding.step,
                credential: SchemaCredential {
                    kind: "bearer",
                    token_ref: secret_ref(&filename),
                },
            });
        }
        let path = self.root.join("schema-test-credentials.json");
        write_private(
            &path,
            &serde_json::to_vec(&SchemaCredentials {
                api_version: SCHEMA_CREDENTIALS_API_VERSION,
                kind: SCHEMA_CREDENTIALS_KIND,
                bindings,
            })?,
        )?;
        Ok(path)
    }

    fn prepare_breg_hooks(&mut self, project: &Path) -> Result<()> {
        let (status, report) = tool_report(
            &self.input.binaries[&Product::Breg].tool,
            "bregctl",
            "explain",
            &["events".as_ref(), project.as_os_str()],
            self.terminate,
        )?;
        ensure!(
            status.success() && report["ok"] == true,
            "bregctl explain events failed"
        );
        let deliveries = report
            .pointer("/explanation/deliveries")
            .and_then(Value::as_array)
            .context("bregctl explain events did not return an event inventory")?;
        let mut destinations = BTreeMap::<String, (u8, u64, u64)>::new();
        for delivery in deliveries {
            let Some(id) = delivery["destinationId"].as_str() else {
                continue;
            };
            registry_platform_yaml::LocalId::new(id)
                .context("invalid BReg hook destination identifier")?;
            let classification = match delivery["classificationCeiling"].as_str() {
                Some("public") => 0,
                Some("internal") => 1,
                Some("restricted") => 2,
                _ => anyhow::bail!("invalid BReg hook classification ceiling"),
            };
            let timeout = delivery["attemptTimeoutMs"]
                .as_u64()
                .context("missing BReg hook timeout")?;
            let maximum_attempts = delivery["maximumAttempts"]
                .as_u64()
                .context("missing BReg hook attempt ceiling")?;
            let limits = destinations.entry(id.to_owned()).or_insert((
                classification,
                timeout,
                maximum_attempts,
            ));
            limits.0 = limits.0.max(classification);
            limits.1 = limits.1.min(timeout);
            limits.2 = limits.2.min(maximum_attempts);
        }
        let external_hooks = self
            .input
            .plan
            .external_breg
            .as_ref()
            .map(|bindings| &bindings.hooks)
            .filter(|hooks| !hooks.is_empty());
        if let Some(hooks) = external_hooks {
            ensure!(
                hooks.keys().eq(destinations.keys()),
                "The external hooks must name exactly the BReg destinations this project declares."
            );
        }
        if destinations.is_empty() {
            return Ok(());
        }
        let sink = if external_hooks.is_none() {
            Some(GatewayServer::start_hooks()?)
        } else {
            None
        };
        let mut hooks = serde_json::Map::new();
        for (id, (classification, timeout, maximum_attempts)) in destinations {
            let file = format!("breg-hook-{id}");
            let (origin, path, key) = if let Some(hooks) = external_hooks {
                let hook = &hooks[&id];
                let key = crate::external_breg::ExternalBreg::hook_key(&self.input.project, hook)?;
                (
                    hook.origin.as_str(),
                    hook.path.as_str(),
                    self.secret(&file, &key)?,
                )
            } else {
                (
                    sink.as_ref()
                        .expect("internal hook receiver")
                        .origin
                        .as_str(),
                    "/events",
                    self.retained_secret("breg", &file, random_secret()?.as_bytes())?,
                )
            };
            let classification = ["public", "internal", "restricted"][usize::from(classification)];
            hooks.insert(
                id,
                json!({
                    "origin": origin,
                    "path": path,
                    "networkProfile": "loopback-http",
                    "dnsFamily": "dual-stack-strict",
                    "allowedPrivateCidrs": [],
                    "hmacSha256KeyRef": key,
                    "classificationCeiling": classification,
                    "deliveryCeilings": {
                        "attemptTimeoutMilliseconds": timeout,
                        "maximumAttempts": maximum_attempts,
                    },
                }),
            );
        }
        write_private(
            &self.root.join("breg-hook-bindings.json"),
            &serde_json::to_vec(&hooks)?,
        )?;
        self.hook_sink = sink;
        Ok(())
    }

    pub(super) fn breg_hook_report(&self) -> Option<Value> {
        self.hook_sink.as_ref().map(|sink| {
            json!({
                "origin": sink.origin,
                "receivedUrl": format!("{}/received", sink.origin),
            })
        })
    }

    fn activate_casework(
        &self,
        database: &mut Database,
        project: &Path,
        bind: &str,
        breg_package: Option<&Path>,
    ) -> Result<PathBuf> {
        let bound;
        let project = if has_run_source(&self.input.plan) {
            bound = self.root.join("casework-bound");
            bind_casework_run_issuer(&self.input.plan, project, &bound)?;
            self.tool(Product::Casework, "check", &[bound.as_os_str()])?;
            bound.as_path()
        } else {
            project
        };
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

    fn activate_additional(
        &self,
        product: Product,
        database: Option<&mut Database>,
        project: &Path,
        bind: &str,
    ) -> Result<PathBuf> {
        let name = product.name();
        let package = self.root.join(format!("{name}-package"));
        if product != Product::Adapter {
            let mut args = Vec::new();
            match product {
                Product::Coordinator | Product::Discovery => args.push("--project".as_ref()),
                Product::Render => args.push("--bundle".as_ref()),
                _ => {}
            }
            args.extend([
                project.as_os_str(),
                "--output".as_ref(),
                package.as_os_str(),
            ]);
            self.tool(product, "package", &args)?;
        }

        let database_urls = if product.needs_database() {
            let urls = database
                .context(NEEDS_DATABASE)?
                .provision(name, false, false)
                .map_err(operational)?;
            self.secret(&format!("{name}-runtime-url"), urls.runtime.as_bytes())?;
            self.secret(&format!("{name}-migration-url"), urls.migration.as_bytes())?;
            Some(urls)
        } else {
            None
        };
        let configuration =
            self.additional_config(product, project, bind, &package, database_urls.as_ref())?;
        let path = self.root.join(format!("{name}-runtime.yaml"));
        write_private(&path, &serde_json::to_vec(&configuration)?)?;

        if matches!(
            product,
            Product::Scheduling | Product::Documents | Product::Coordinator
        ) {
            let args = ["--runtime-config".as_ref(), path.as_os_str()];
            self.tool(product, "apply", &args)?;
            if product == Product::Scheduling {
                self.apply_scheduling_records(project, &path)?;
            }
        }
        Ok(path)
    }

    fn apply_scheduling_records(&self, project: &Path, config: &Path) -> Result<()> {
        let source = project.join("records.yaml");
        let retained = self
            .product_state("scheduling")
            .map(|state| {
                let bytes = plan::read(
                    &source,
                    registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES as u64,
                )?;
                let digest = registry_platform_config::sha256_uri(&bytes);
                Ok::<_, anyhow::Error>((state.join("scheduling-records-digest"), bytes, digest))
            })
            .transpose()?;
        let records = if let Some((state, bytes, digest)) = &retained {
            if super::read_private(state)?.as_deref() == Some(digest.as_bytes()) {
                return Ok(());
            }
            let captured = self.root.join("scheduling-records.yaml");
            write_private(&captured, bytes)?;
            captured
        } else {
            source
        };
        self.tool(
            Product::Scheduling,
            "records",
            &[
                "apply".as_ref(),
                "--runtime-config".as_ref(),
                config.as_os_str(),
                records.as_os_str(),
            ],
        )?;
        if let Some((state, _, digest)) = retained {
            write_private(&state, digest.as_bytes())?;
        }
        Ok(())
    }

    fn additional_config(
        &self,
        product: Product,
        project: &Path,
        bind: &str,
        package: &Path,
        urls: Option<&DatabaseUrls>,
    ) -> Result<Value> {
        let name = product.name();
        let identity = self.database_identity(name);
        let (mut config, mut oidc) = shared_config(
            &self.input.plan,
            product,
            name,
            self.root,
            package,
            &BTreeSet::new(),
        );
        config["audit"]["path"] = json!(self.audit_path(name));
        config["apiVersion"] = json!(format!(
            "id.registrystack.org/formats/{name}/runtime/v1alpha1"
        ));
        config["listener"] = json!({"bind": bind, "tlsTermination": "loopback-plaintext"});
        match product {
            Product::Scheduling | Product::Documents => {
                self.retained_secret(
                    name,
                    &format!("{name}-audit-key"),
                    random_secret()?.as_bytes(),
                )?;
                config["kind"] = json!(if product == Product::Scheduling {
                    "SchedulingRuntimeConfig"
                } else {
                    "DocumentsRuntimeConfig"
                });
                config["identity"] = json!({"databaseId": identity});
                config["authentication"] = json!({"oidc": issuer_set(oidc)});
                if product == Product::Scheduling {
                    config["taskGrantStatus"] = json!("unchecked-final-fifteen-minutes");
                    config["retention"] = json!({});
                } else {
                    config["storage"] = json!({"type": "database"});
                    config["contentVerification"] = json!({"type": "disabled"});
                    config["cleanup"] = json!({"erasure": "active"});
                }
            }
            Product::Coordinator => {
                let runtime = authored_document(&project.join("runtime.yaml"))?;
                let workflow = authored_document(&project.join("workflow.yaml"))?;
                let workflow_id = workflow
                    .pointer("/project/id")
                    .and_then(Value::as_str)
                    .context("coordinator workflow does not name an id")?;
                let checksum =
                    registry_platform_config::sha256_uri(&fs::read(package.join("SHA256SUMS"))?);
                let mut policies = serde_json::Map::new();
                for person in self.input.plan.people.values() {
                    if let Some(grant) = person.grants.get(&product) {
                        let policy = policies.entry(person.client.clone()).or_insert_with(|| json!({
                            "subjects": [], "requiredScopes": grant.scopes, "workflows": [workflow_id],
                            "actions": ["status", "start"]
                        }));
                        let subjects = policy["subjects"].as_array_mut().expect("subjects array");
                        if !subjects.contains(&json!(person.subject)) {
                            subjects.push(json!(person.subject));
                        }
                    }
                }
                oidc["allowedClients"] = json!("from-policies");
                let mut authentication = issuer_set(oidc);
                authentication["policies"] = json!(policies);
                let key = |file| self.retained_secret(name, file, random_key_bytes()?.as_slice());
                let mut connections = runtime["connections"].clone();
                if let Some(connections) = connections.as_object_mut() {
                    for (id, connection) in connections {
                        registry_platform_yaml::LocalId::new(id.as_str())
                            .context("invalid Coordinator connection identifier")?;
                        for field in ["authorization", "observationAuthorization"] {
                            let Some(authorization) =
                                connection.get_mut(field).and_then(Value::as_object_mut)
                            else {
                                continue;
                            };
                            if self.input.plan.jwks_uri().is_some() {
                                continue;
                            }
                            let origin = self
                                .coordinator_issuer
                                .as_ref()
                                .context("missing Coordinator development issuer")?
                                .origin();
                            let client_key = registry_platform_crypto::generate_private_jwk(
                                registry_platform_crypto::GeneratedKeyAlgorithm::Es256,
                            )?;
                            let reference = self.retained_secret(
                                name,
                                &format!("coordinator-{id}-{field}-key"),
                                &super::bindings::encode_private_jwk(&client_key)?,
                            )?;
                            // The starter reads workflow metadata. Its outbound
                            // clients cannot acquire tokens from an external issuer.
                            authorization
                                .insert("tokenEndpoint".into(), json!(format!("{origin}/token")));
                            authorization.insert("clientAssertionAudience".into(), json!(origin));
                            authorization.insert("signingKeyRef".into(), json!(reference));
                        }
                    }
                }
                return Ok(json!({
                    "apiVersion": config["apiVersion"],
                    "kind": "CoordinatorRuntimeConfig",
                    "secretProviders": config["secretProviders"],
                    "database": config["database"],
                    "namespace": "coordinator_dev",
                    "connections": connections,
                    "deployment": {
                        "databaseId": identity,
                        "runtimeRole": url::Url::parse(&urls.context(NEEDS_DATABASE)?.runtime)?.username(),
                        "packages": [{"root": package, "expectedDigest": checksum}],
                        "listener": config["listener"],
                        "authentication": authentication,
                        "auditFile": config["audit"]["path"],
                        "auditKeyRef": key("coordinator-audit-key")?,
                        "activeStateKey": 1,
                        "stateKeys": {"1": {"keyRef": key("coordinator-state-key")?}},
                        "admissionKeyRef": key("coordinator-admission-key")?,
                    }
                }));
            }
            Product::Adapter => {
                let template = authored_document(&project.join("runtime.example.yaml"))?;
                let mut endpoints = template["endpoints"]
                    .as_array()
                    .context("adapter development endpoints must be an array")?
                    .clone();
                for (index, endpoint) in endpoints.iter_mut().enumerate() {
                    let url = endpoint["baseUrl"]
                        .as_str()
                        .context("adapter development endpoint needs a loopback URL")?;
                    ensure!(
                        url::Url::parse(url)?.host().is_some_and(|host| match host {
                            url::Host::Ipv4(address) => address.is_loopback(),
                            url::Host::Ipv6(address) => address.is_loopback(),
                            url::Host::Domain(_) => false,
                        }),
                        "adapter development endpoints must use a numeric loopback URL"
                    );

                    if endpoint["credential"]["type"] == "basic" {
                        endpoint["credential"] = json!({
                            "type": "basic",
                            "usernameRef": self.secret(&format!("adapter-upstream-{index}-username"), b"development")?,
                            "passwordRef": self.secret(&format!("adapter-upstream-{index}-password"), random_secret()?.as_bytes())?,
                        });
                    }
                }
                oidc.as_object_mut()
                    .expect("OIDC object")
                    .remove("scopeClaim");
                return Ok(json!({
                    "apiVersion": config["apiVersion"],
                    "kind": "AdapterRuntimeConfig",
                    "id": identity,
                    "endpoints": endpoints,
                    // The Adapter policy requires a nonempty list. The authored
                    // endpoints above must still be numeric loopback addresses.
                    "allowedPrivateCidrs": ["10.0.0.1/32"],
                    "listener": {"bind": bind},
                    "database": config["database"],
                    "secretProviders": config["secretProviders"],
                    "oidc": issuer_set(oidc),
                    "audit": {"retentionDays": 1},
                    "idempotency": {"responseRetentionSeconds": 3600},
                    "cursorKeyRef": self.retained_secret(name, "adapter-cursor-key", random_key_bytes()?.as_slice())?,
                }));
            }
            Product::Render => {
                oidc.as_object_mut()
                    .expect("OIDC object")
                    .remove("scopeClaim");
                return Ok(json!({
                    "apiVersion": config["apiVersion"],
                    "kind": "RenderRuntimeConfig",
                    "listener": {"bind": bind},
                    "package": config["package"],
                    "secretProviders": config["secretProviders"],
                    "authentication": {"oidc": issuer_set(oidc)},
                    "audit": {"path": config["audit"]["path"]},
                }));
            }
            Product::Discovery => {
                return Ok(json!({
                    "apiVersion": config["apiVersion"],
                    "kind": "DiscoveryRuntimeConfig",
                    "listener": {"bind": bind, "requestTimeoutMilliseconds": 10_000},
                    "package": config["package"],
                    "limits": {
                        "maximumRequestBytes": 65_536,
                        "maximumResponseBytes": 1_048_576,
                        "maximumResultRecords": 100,
                        "maximumResultAlternatives": 100,
                        "shutdownGraceMilliseconds": 10_000,
                    },
                    "logLevel": "info",
                }));
            }
            _ => unreachable!("only additional products use this configuration"),
        }
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
        self.retained_secret(
            name,
            &format!("{name}-audit-key"),
            random_secret()?.as_bytes(),
        )?;
        let identity = self.database_identity(name);
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
                oidc["allowedAlgorithm"] = json!(if plan.jwks_uri().is_some() {
                    "RS256"
                } else {
                    "ES256"
                });
                oidc["accessTokenType"] = json!("at+jwt");
                oidc["scopeSeparator"] = json!(" ");
                oidc["maximumTokenLifetimeSeconds"] = json!(super::issuer::TOKEN_LIFETIME_SECONDS);
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
                // The run initializes a disposable database under the development posture.
                config["identity"] = json!({
                    "environment": "local", "instanceId": identity,
                    "databaseId": identity
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
                    "oidc": issuer_set(oidc),
                    "authorityClaims": authority_claims
                });
                config["cursor"] = json!({
                    "secretRef": self.retained_secret(name, &format!("{name}-cursor-key"), random_secret()?.as_bytes())?, "maximumAgeSeconds": 300
                });
                let bindings = match fs::read(self.root.join("breg-hook-bindings.json")) {
                    Ok(bytes) => serde_json::from_slice::<Value>(&bytes)?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({}),
                    Err(error) => return Err(error.into()),
                };
                config["destinations"] = json!({"hooks": bindings});
                if let Some(external) = &plan.external_breg {
                    external.configure(
                        |file, bytes| self.secret(file, bytes),
                        &self.input.project,
                        &plan.issuer,
                        &mut config,
                    )?;
                }
                config["operationalTimeouts"] = json!({
                    "httpRequestMilliseconds": 10000, "shutdownGraceMilliseconds": 1000,
                    "recordLockMilliseconds": 5000, "migrationLockMilliseconds": 30000,
                    "migrationStatementMilliseconds": 60000
                });
                config
            }
            Product::Casework => casework_config(plan, name, self.root, package, &identity, bind),
            Product::Messaging => {
                let mut config = messaging::messaging_config(
                    plan,
                    name,
                    self.root,
                    package,
                    &identity,
                    bind,
                    self.messaging_providers.as_ref(),
                );
                let metrics = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?;
                config["metricsListener"] = json!({"bind": metrics.to_string()});
                config
            }
            Product::Evidence => {
                unreachable!("Evidence writes its runtime configuration by packaging")
            }
            _ => unreachable!("additional products write their own runtime configuration"),
        };
        config["audit"]["path"] = json!(self.audit_path(name));
        if let Some(bindings) = &self.bindings {
            bindings.configure(product, &mut config);
        }
        let path = self.root.join(format!("{name}-runtime.yaml"));
        write_private(&path, &serde_json::to_vec(&config)?)?;
        Ok(path)
    }

    fn product_state(&self, name: &str) -> Option<PathBuf> {
        self.input
            .project_state(self.root)
            .filter(|_| name != "breg-test")
    }

    fn database_identity(&self, name: &str) -> String {
        let id = self
            .input
            .project_key
            .as_deref()
            .filter(|_| name != "breg-test")
            .unwrap_or(&self.input.run_id);
        format!("dev-{id}-{name}")
    }

    fn audit_path(&self, name: &str) -> PathBuf {
        let state = self.product_state(name);
        state
            .as_deref()
            .unwrap_or(self.root)
            .join(format!("{name}-audit"))
            .join("audit.jsonl")
    }

    fn retained_secret(&self, product: &str, name: &str, fresh: &[u8]) -> Result<String> {
        let Some(state) = self.product_state(product) else {
            return self.secret(name, fresh);
        };
        let bytes = self.kept_key(&state, name, |path| write_private(path, fresh))?;
        self.secret(name, &bytes)
    }

    fn secret(&self, name: &str, bytes: &[u8]) -> Result<String> {
        write_private(&self.root.join(name), bytes)?;
        Ok(secret_ref(name))
    }

    fn tool(&self, product: Product, stage: &str, args: &[&std::ffi::OsStr]) -> Result<()> {
        self.ensure_active()?;
        let mut arguments = vec![std::ffi::OsStr::new(stage)];
        arguments.extend_from_slice(args);
        if !matches!(
            (product, stage),
            (Product::Discovery | Product::Render, "package")
        ) {
            arguments.extend(["--format", "json"].map(std::ffi::OsStr::new));
        }
        run_logged_tool(
            &self.input.binaries[&product].tool,
            &arguments,
            self.root,
            (product.name(), stage),
            product == Product::Casework && has_run_source(&self.input.plan),
            || self.ensure_active(),
        )
    }

    /// Record every live runtime group for status diagnostics and manual
    /// cleanup evidence. Guards, not this record, own process lifetime.
    fn record_processes(&self) -> Result<()> {
        let entries: Vec<_> = self
            .children
            .iter()
            .map(|(kind, child)| (*kind, child.id()))
            .collect();
        write_processes(self.root, &entries)
    }

    fn ready(&mut self, kind: RuntimeKind, base: &str, path: &str, wait: Duration) -> Result<()> {
        let end = Instant::now() + wait;
        let url = format!("{base}{path}");
        loop {
            self.ensure_active()?;
            self.ensure_alive(kind)?;
            if self
                .runtime
                .block_on(async { self.http.get(&url).send().await })
                .is_ok_and(|response| response.status().is_success())
            {
                self.ensure_alive(kind)?;
                return Ok(());
            }
            if Instant::now() >= end {
                return Err(operational(anyhow::anyhow!(
                    "{} did not become ready{}",
                    kind.name(),
                    self.runtime_log_tail(kind)
                )));
            }
            thread::sleep(POLL);
        }
    }

    /// Fail while waiting on `waiting`, naming whichever child exited.
    fn ensure_alive(&self, waiting: RuntimeKind) -> Result<()> {
        for (kind, child) in &self.children {
            if child.exited()? {
                let detail = self.runtime_log_tail(*kind);
                if *kind == waiting {
                    bail!("{} exited before readiness{detail}", kind.name());
                }
                bail!(
                    "{} exited while {} was starting{detail}",
                    kind.name(),
                    waiting.name()
                );
            }
        }
        Ok(())
    }

    fn runtime_log_tail(&self, kind: RuntimeKind) -> String {
        failure_detail(&log_path(self.root, &format!("{}-runtime", kind.name())))
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
        self.children.retain_mut(|(kind, child)| {
            if child.stop().is_err() {
                failures.push(kind.name());
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
        drop(self.jwks.take());
        drop(self.coordinator_issuer.take());
        drop(self.gateway.take());
        drop(self.hook_sink.take());
        Ok(())
    }

    pub(super) fn journey(
        &self,
        issuer: &Issuer,
        urls: &BTreeMap<Product, String>,
        journey: &plan::Journey,
    ) -> Result<super::journey::JourneyReport> {
        super::journey::run(&self.input, issuer, urls, journey, || self.ensure_active())
    }
}

/// Coordinator binds the token endpoint into its live workflows. Keep the
/// local issuer address as long as those workflows can be resumed.
fn needs_stable_issuer(runtime: &Value, external_jwks: Option<&str>) -> bool {
    external_jwks.is_none()
        && runtime["connections"]
            .as_object()
            .is_some_and(|connections| {
                connections.values().any(|connection| {
                    ["authorization", "observationAuthorization"]
                        .iter()
                        .any(|field| connection[*field].is_object())
                })
            })
}

fn coordinator_issuer_listener(state: Option<&Path>) -> Result<TcpListener> {
    let Some(state) = state else {
        return Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?);
    };
    let file = state.join("coordinator-issuer-port");
    let port = match super::read_private(&file)? {
        Some(saved) => std::str::from_utf8(&saved)?
            .parse::<std::num::NonZeroU16>()
            .context("the retained Coordinator issuer port is invalid")?
            .get(),
        None => 0,
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).with_context(|| {
        format!("cannot bind the Coordinator development issuer on loopback port {port}, which is kept for resumable workflow connections. Start with --clean")
    })?;
    if port == 0 {
        write_private(&file, listener.local_addr()?.port().to_string().as_bytes())?;
    }
    Ok(listener)
}

fn log_path(root: &Path, name: &str) -> PathBuf {
    root.join("logs").join(format!("{name}.log"))
}

pub(super) fn valid_health_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains(['?', '#', '\\'])
        && !path.chars().any(char::is_control)
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
    retain_receipt: bool,
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
    if stage == "apply" && !status.success() {
        let unchanged = match product {
            "casework" => Some("casework.activation.already-active"),
            "scheduling" => Some("schedulingctl.activation.package-already-active"),
            _ => None,
        };
        if let Some(code) = unchanged {
            output.rewind()?;
            let mut bytes = Vec::new();
            (&mut output)
                .take(MAX_TOOL_REPORT + 1)
                .read_to_end(&mut bytes)?;
            if serde_json::from_slice::<Value>(&bytes)
                .is_ok_and(|report| only_refusal(&report, code))
            {
                return Ok(());
            }
            output.rewind()?;
        }
    }
    logged_tool_result(status, &mut output, root, (product, stage))?;
    if retain_receipt {
        retain_tool_receipt(&mut output, root, product, stage)?;
    }
    Ok(())
}

fn retain_tool_receipt(
    output: &mut fs::File,
    root: &Path,
    product: &str,
    stage: &str,
) -> Result<()> {
    output.rewind()?;
    let mut bytes = Vec::new();
    output.take(MAX_TOOL_REPORT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_TOOL_REPORT,
        "product receipt exceeds the run limit"
    );
    let report: Value = serde_json::from_slice(&bytes).context("invalid product receipt")?;
    let command = if stage == "provider" {
        "provider-pair"
    } else {
        stage
    };
    ensure!(
        report["ok"] == true
            && report["command"] == command
            && report["status"] == "complete"
            && report["kind"] == "CaseworkReport"
            && report["apiVersion"] == CASEWORK_REPORT_API_VERSION,
        "product did not return its exact successful receipt"
    );
    write_private(
        &root.join(format!("{product}-{stage}-receipt.json")),
        &bytes,
    )
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub(super) struct LoggedToolFailure {
    message: String,
    codes: BTreeSet<String>,
    status: ExitStatus,
}

impl LoggedToolFailure {
    pub(super) fn operational(&self) -> bool {
        registry_cli_report::Status::from_exit(self.status.code().unwrap_or(3) as u8)
            == registry_cli_report::Status::OperationalFailure
    }
}

fn retained_breg_refusal(
    error: anyhow::Error,
    has_baseline: bool,
    changes: &[String],
) -> anyhow::Error {
    let retention_refusal = error
        .downcast_ref::<LoggedToolFailure>()
        .is_some_and(|failure| {
            failure.codes.iter().any(|code| {
                matches!(
                    code.as_str(),
                    "migration.review.required"
                        | "migration.change.unsupported"
                        | "migration.rehearsal.baseline-fingerprint-drift"
                        | "migration.rehearsal.baseline-unavailable"
                        | "migration.rehearsal.baseline-not-reproducible"
                        | "apply.package.active-mismatch"
                        | "apply.package.fingerprint-mismatch"
                        | "apply.successor.roles-differ"
                )
            })
        });
    if has_baseline && retention_refusal {
        error.context(format!(
            "BReg refused changes to the retained package ({}). Start with --clean",
            changes.join(", ")
        ))
    } else {
        error
    }
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
    let mut bytes = Vec::new();
    output.take(MAX_TOOL_REPORT + 1).read_to_end(&mut bytes)?;
    let report = (bytes.len() as u64 <= MAX_TOOL_REPORT)
        .then(|| serde_json::from_slice::<Value>(&bytes).ok())
        .flatten();
    if product == "breg" && stage == "test" {
        // The tool's own report is the failure record; the runner adds nothing.
        ensure!(
            bytes.len() as u64 <= MAX_TOOL_REPORT,
            "the breg test report exceeds the run limit"
        );
        write_private(&root.join("logs/breg-test-report.json"), &bytes)?;
    }
    let shown = report_codes(bytes.as_slice())?;
    let codes = report
        .as_ref()
        .and_then(|report| report["diagnostics"].as_array())
        .into_iter()
        .flatten()
        .filter(|item| item["severity"] == "error")
        .filter_map(|item| item["code"].as_str().map(str::to_owned))
        .collect();
    Err(LoggedToolFailure {
        message: format!(
            "{product} {stage} failed{shown}{}",
            failure_detail(&log_path(root, &format!("{product}-{stage}")))
        ),
        status,
        codes,
    }
    .into())
}

/// Exercise the log/result boundary in unit tests without routing a shell
/// through the Rust test harness as if it were a host CLI. The rstack
/// `dev_run` integration test covers the real hidden guard dispatch.
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

/// Record each runtime process group for diagnostics and an operator's manual
/// cleanup decision. Children start as group leaders, so the group ID is the
/// PID.
fn write_processes(root: &Path, children: &[(RuntimeKind, u32)]) -> Result<()> {
    let entries: Vec<_> = children
        .iter()
        .map(|(kind, pid)| match kind {
            RuntimeKind::Product(product) => {
                json!({"product": product.name(), "pid": pid, "pgid": pid})
            }
            RuntimeKind::Application => {
                json!({"application": "application", "pid": pid, "pgid": pid})
            }
        })
        .collect();
    write_private(&root.join("processes.json"), &serde_json::to_vec(&entries)?)
}

/// The reference to the secret the run writes as `name` in its directory.
fn secret_ref(name: &str) -> String {
    format!("secret:file/{name}")
}

fn breg_package_arguments<'a>(
    project: &'a Path,
    receipt: &'a Path,
    build: &'a Path,
) -> [&'a std::ffi::OsStr; 7] {
    [
        project.as_os_str(),
        "--test-receipt".as_ref(),
        receipt.as_os_str(),
        "--output".as_ref(),
        build.as_os_str(),
        "--posture".as_ref(),
        super::DEVELOPMENT.as_ref(),
    ]
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
            plan.application
                .iter()
                .filter(|_| {
                    matches!(
                        product,
                        Product::Breg | Product::Casework | Product::Messaging
                    )
                })
                .map(|application| application.client.as_str()),
        )
        .chain(extra_clients.iter().map(String::as_str))
        .collect();
    let oidc = json!({
        "issuer": plan.issuer,
        "audience": plan.product(product).audience,
        "allowedClients": clients,
        "scopeClaim": "scope",
        "jwksSource": plan.jwks_uri().map_or_else(
            || json!({"type": "test-issuer", "documentRef": secret_ref("jwks")}),
            |uri| json!({"type": "uri", "uri": uri}),
        )
    });
    let mut database = json!({
        "runtimeUrlRef": secret_ref(&format!("{name}-runtime-url")),
        "migrationUrlRef": secret_ref(&format!("{name}-migration-url"))
    });
    if root.join("postgres-ca").is_file() {
        database["caBundleRef"] = json!(secret_ref("postgres-ca"));
    }
    let audit = json!({
        "hashKeyRef": secret_ref(&format!("{name}-audit-key")),
        "hashKeyCustody": "development-generated",
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

/// The issuer set a product reads: the run issuer as its one entry, `main`.
pub(super) fn issuer_set(entry: Value) -> Value {
    json!({"issuers": {"main": entry}})
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
    let (mut config, mut oidc) = shared_config(
        plan,
        Product::Casework,
        name,
        root,
        package,
        &BTreeSet::new(),
    );
    config["apiVersion"] = json!("id.registrystack.org/formats/casework/runtime/v1alpha1");
    config["kind"] = json!("CaseworkRuntimeConfig");
    oidc["maximumTokenLifetimeSeconds"] = json!(super::issuer::TOKEN_LIFETIME_SECONDS);
    config["listener"] = json!({"bind": bind, "tlsTermination": "loopback-plaintext"});
    config["identity"] = json!({"databaseId": identity});
    // Casework reads its issuers as a set, and the run has one.
    config["authentication"] = json!({"oidc": issuer_set(oidc)});
    config
}

fn authored_document(path: &Path) -> Result<Value> {
    use registry_platform_yaml::{Reader, MAXIMUM_DOCUMENT_BYTES};
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAXIMUM_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAXIMUM_DOCUMENT_BYTES,
        "project document exceeds the development limit"
    );
    Reader::new(path.display().to_string())
        .scan(&bytes)?
        .map(|node| node.to_json_value())
        .context("project document is empty")
}

fn random_key_bytes() -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| anyhow::anyhow!("cannot generate a local key"))?;
    Ok(bytes)
}

fn random_secret() -> Result<zeroize::Zeroizing<String>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let bytes = random_key_bytes()?;
    let mut encoded = zeroize::Zeroizing::new(String::new());
    URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut encoded);
    Ok(encoded)
}

/// Copies a project into the run. The copy is private to the owner whatever
/// the caller's umask, because products refuse a secret directory that other
/// users can read.
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
        super::private_directory(target)?;
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
                fs::copy(entry.path(), &destination)?;
                let owner_only = info.permissions().mode() & 0o700;
                fs::set_permissions(&destination, fs::Permissions::from_mode(owner_only))?;
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

/// The error for an inspection that could not complete. An interrupt is the
/// operator's request and stays as it is. Any other failure is an unavailable
/// inspection whose reason keeps the cause; the cause comes from spawning the
/// tool, its timeout, temporary files and the report parse, and none of those
/// messages carries a configured value.
fn inspection_failed(
    product: Product,
    field: &str,
    action: &str,
    error: anyhow::Error,
    terminate: &AtomicBool,
) -> anyhow::Error {
    if terminate.load(Ordering::Relaxed) {
        return error;
    }
    let (tool, variable) = super::product_tool_info(product);
    InspectionUnavailable::new(
        field,
        &format!("The selected `{tool}` helper could not {action}: {error:#}."),
        &format!(
            "Install the matching {} tools or provide {variable}, then run the check again.",
            product.name()
        ),
    )
    .into()
}

struct SelectedProduct {
    field: String,
    root: PathBuf,
}

/// Check that the canonical-review starter is paired with its BReg project.
pub(super) fn require_canonical_review_pair(root: &Path, plan: &Plan) -> Result<()> {
    if plan.bindings.casework_context_provider.is_some() {
        return Ok(());
    }
    let Some(project) = product_root(root, plan, Product::Casework)? else {
        return Ok(());
    };
    let policy = authored_document(&project.root.join("casework.yaml"))?;
    let provider = &policy["contextProviders"]["facility-proposal-context"];
    ensure!(
        policy["project"]["id"] != "canonical-review" || provider.is_null() || !provider["description"].is_null(),
        "Canonical review needs its facility-registry BReg project paired with `caseworkctl provider pair PROJECT --provider-id facility-proposal-context --breg-package BREG_PACKAGE --action-id correct-address --apply`."
    );
    Ok(())
}

/// Whether the project's Messaging providers need the run to start Mailpit.
pub(super) fn needs_mailpit(root: &Path, plan: &Plan) -> Result<bool> {
    messaging::needs_mailpit(root, plan)
}

pub(super) fn inspect(
    root: &Path,
    plan: &Plan,
    terminate: &AtomicBool,
) -> Result<ProductInspection> {
    let breg_authority = breg_authority(root, plan, terminate)?;
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
    let manifest_name = product.manifest();
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

fn breg_authority(
    root: &Path,
    plan: &Plan,
    terminate: &AtomicBool,
) -> Result<Option<BregAuthority>> {
    let Some(project) = product_root(root, plan, Product::Breg)? else {
        return Ok(None);
    };
    let tool = super::product_tool(Product::Breg).map_err(|_| {
        InspectionUnavailable::new(
            &project.field,
            "The BReg project cannot be inspected because its owning tool is unavailable.",
            "Install the matching BReg tools or provide RSTACK_BREGCTL_BIN, then run the check again.",
        )
    })?;
    let facts = match breg_facts(&tool, &project.root, terminate) {
        Ok(facts) => facts,
        Err(error) => match error.downcast::<InvalidBregProject>() {
            Ok(invalid) => return Err(breg_validation_refusal(&project.field, &invalid).into()),
            Err(error) => {
                return Err(inspection_failed(
                    Product::Breg,
                    &project.field,
                    "inspect the BReg project",
                    error,
                    terminate,
                ))
            }
        },
    };
    validate_breg_binding_ids(&plan.bindings, &facts)?;
    if let Some(external) = &plan.external_breg {
        if let Some(review) = &external.review_authority {
            plan::require(
                plan.bindings.breg_review_authority.is_none()
                    && facts.review_authorities.contains(review.id.as_str()),
                "/externalBreg/reviewAuthority/id",
                "This BReg project needs the named review authority and cannot bind it to two producers.",
                "Declare this review authority in registry.yaml and remove the paired synthetic binding.",
            )?;
        }
        if let Some(grant) = &external.task_grant {
            let authored = authored_document(&project.root.join("registry.yaml"))?;
            let has_task_profile = authored["accessProfiles"]
                .as_object()
                .is_some_and(|profiles| {
                    profiles
                        .values()
                        .any(|profile| !profile["taskGrant"].is_null())
                });
            plan::require(
                has_task_profile && facts.named_clients.contains(&grant.assertion_client),
                "/externalBreg/taskGrant/assertionClient",
                "This BReg project needs a task-grant profile and must name the exact assertion client.",
                "Declare taskGrant and the registered assertion client in a BReg access profile.",
            )?;
        }
    }
    check_breg_grants(&facts, &plan.people)?;
    let principal = breg_principal(plan, &facts.principal_claims)?;
    Ok(Some(BregAuthority {
        principal,
        purpose: facts.purpose_required,
        named_clients: facts.named_clients,
        requires_postgis: facts.requires_postgis,
        encrypts_fields: facts.encrypts_fields,
    }))
}

/// The refusal for a BReg project its owning tool rejected. It carries the
/// tool's own diagnostics (file, line, message, suggested action) so the
/// adopter does not need a second command to learn what to correct.
fn breg_validation_refusal(field: &str, invalid: &InvalidBregProject) -> plan::SemanticRefusal {
    plan::SemanticRefusal::new(
        field,
        format!(
            "The BReg project did not pass its owning validation: {}.",
            invalid.findings
        ),
        format!(
            "Correct the BReg project where the diagnostics point (suggested action: {}).",
            invalid.actions
        ),
    )
}

/// The principal claim the project's access profiles select. Distinct claims
/// across profiles are refused by `bregctl` when it loads the runtime
/// configuration (`PrincipalClaimMismatch`, `crates/registry-breg/src/auth.rs`).
fn breg_principal(
    plan: &Plan,
    principal_claims: &BTreeSet<String>,
) -> plan::SemanticResult<String> {
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

fn validate_breg_binding_ids(bindings: &Bindings, facts: &BregFacts) -> plan::SemanticResult<()> {
    if let Some(binding) = &bindings.breg_review_authority {
        plan::require(
            facts.review_authorities.contains(&binding.id),
            "/bindings/bregReviewAuthority/id",
            "The BReg review authority ID does not name a review authority in the BReg project.",
            "Set id to a review authority defined by the BReg project.",
        )?;
    }
    if let Some(binding) = &bindings.casework_context_provider {
        plan::require(
            facts.actions.contains(&binding.action),
            "/bindings/caseworkContextProvider/action",
            "The Casework context provider action does not name an action in the BReg project.",
            "Set action to an action defined by the BReg project.",
        )?;
    }
    Ok(())
}

/// Every BReg grant must name an access profile the project declares,
/// including profiles that carry only proposal permissions and so belong to no
/// entity. Scopes are not checked here: a profile's required scopes are a
/// per-entity rule the runtime applies, and a mismatch surfaces when the
/// journey runs.
fn check_breg_grants(
    facts: &BregFacts,
    people: &BTreeMap<String, plan::TestPerson>,
) -> plan::SemanticResult<()> {
    for (name, person) in people {
        if let Some(grant) = person.grants.get(&Product::Breg) {
            plan::require(
                facts.access_profiles.contains(&grant.profile),
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
            let findings = error
                .downcast_ref::<InvalidCaseworkProject>()
                .map(|invalid| invalid.findings.as_str())
                .unwrap_or_default();
            return Err(plan::SemanticRefusal::new(
                &project.field,
                format!(
                    "The Casework project did not pass validation by its owning tool: {findings}."
                ),
                "Correct the Casework project where the diagnostics point.",
            )
            .into());
        }
        Err(error) => {
            return Err(inspection_failed(
                Product::Casework,
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
    if has_run_source(plan) {
        checked_casework_run_issuer(plan, &project.root)?;
    }
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
        return Err(InvalidCaseworkProject {
            findings: casework_findings(&report),
        }
        .into());
    }
    anyhow::bail!("caseworkctl explain did not complete successfully")
}

/// Runs `<tool> --format json <command> <arguments>` and returns its exit
/// status with the JSON report it printed. `name` is the tool's name in errors.
pub(super) fn tool_report(
    tool: &Path,
    name: &str,
    command: &str,
    arguments: &[&std::ffi::OsStr],
    terminate: &AtomicBool,
) -> Result<(ExitStatus, Value)> {
    let mut child = child_command(tool)
        .args(["--format", "json", command])
        .args(arguments)
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot start {name} {command}"))?;
    let stdout = child.stdout.take().expect("the report output was piped");
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(MAX_TOOL_REPORT + 1).read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = wait_for_tool(&mut child, || {
        ensure!(
            !terminate.load(Ordering::Relaxed),
            "development product inspection was interrupted"
        );
        ensure!(Instant::now() < deadline, "{name} {command} timed out");
        Ok(())
    })?;
    let bytes = reader
        .join()
        .map_err(|_| anyhow::anyhow!("cannot collect the {name} {command} report"))??;
    ensure!(
        bytes.len() as u64 <= MAX_TOOL_REPORT,
        "the {name} {command} report exceeds the size limit"
    );
    let report = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("{name} {command} did not emit a JSON report"))?;
    Ok((status, report))
}

fn casework_domain_refusal(report: &Value, command: &str) -> bool {
    report["apiVersion"] == CASEWORK_REPORT_API_VERSION
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
        config["authentication"]["oidc"]["issuers"]["main"]["issuer"] =
            json!(super::bindings::issuer_for_check(plan));
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
        Err(error) => {
            return Err(inspection_failed(
                Product::Casework,
                &project.field,
                action,
                error,
                terminate,
            ))
        }
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
            Product::Casework,
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
        && report["apiVersion"] == CASEWORK_REPORT_API_VERSION
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
#[error("the Casework project did not pass its owning validation: {findings}")]
struct InvalidCaseworkProject {
    /// The owning tool's error diagnostics, one `path: message` entry each.
    findings: String,
}

fn casework_findings(report: &Value) -> String {
    report["diagnostics"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|diagnostic| diagnostic["severity"] == "error")
        .filter_map(|diagnostic| {
            Some(format!(
                "{}: {}",
                diagnostic["path"].as_str()?,
                diagnostic["message"].as_str()?.trim_end_matches('.')
            ))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

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
        report["apiVersion"] == CASEWORK_REPORT_API_VERSION
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
        .env(super::POSTURE_ENV, super::DEVELOPMENT)
        .env_remove("RSTACK_DEV_DATABASE_URL")
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

fn only_refusal(report: &Value, code: &str) -> bool {
    let mut errors = report["diagnostics"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| item["severity"] == "error");
    errors.next().is_some_and(|item| item["code"] == code) && errors.next().is_none()
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

/// One step of `tests/journeys.yaml`, with the members the runner uses to bind
/// the step to a test person. The owning `bregctl test` validates the file.
struct JourneyStep {
    journey_id: String,
    step_id: String,
    access_profile: String,
    /// The step's `claims.scopes`, or `None` when it writes no `scopes`.
    scopes: Option<Vec<String>>,
    purpose: Option<String>,
}

fn journey_steps(path: &Path, bytes: &[u8]) -> Result<Vec<JourneyStep>> {
    let document = registry_platform_yaml::Reader::new(path.display().to_string())
        .scan(bytes)
        .map_err(|_| anyhow::anyhow!("the journeys file is not valid YAML"))?
        .context("the journeys file is empty")?
        .to_json_value();
    let text = |value: &Value, member: &str| {
        value[member]
            .as_str()
            .map(str::to_owned)
            .with_context(|| format!("a journeys entry has no {member}"))
    };
    let mut steps = Vec::new();
    for journey in document["journeys"]
        .as_array()
        .context("the journeys file has no journeys")?
    {
        for step in journey["steps"]
            .as_array()
            .context("a journey has no steps")?
        {
            let scopes = match step["claims"].get("scopes") {
                Some(scopes) => Some(
                    scopes
                        .as_array()
                        .context("a step's claims.scopes is not a list")?
                        .iter()
                        .map(|scope| {
                            scope
                                .as_str()
                                .map(str::to_owned)
                                .context("a step scope is not text")
                        })
                        .collect::<Result<_>>()?,
                ),
                None => None,
            };
            steps.push(JourneyStep {
                journey_id: text(journey, "id")?,
                step_id: text(step, "id")?,
                access_profile: text(step, "accessProfile")?,
                scopes,
                purpose: step["claims"]["purpose"].as_str().map(str::to_owned),
            });
        }
    }
    Ok(steps)
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
    let steps = match journey_steps(&canonical, &bytes) {
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

/// The dev.yaml member that carries the run issuer binding.
const RUN_ISSUER_BINDING: &str = "/bindings/bregReviewAuthority/runIssuerBinding";

/// Writes the run's loopback issuer into a copy of the Casework project at
/// `bound`. The source project is never edited. The copy changes only the
/// selected producer's `issuer`, and its `trustedInitiatorIssuer` when the
/// binding names an initiator. The caller then runs the public `caseworkctl
/// check` and `package` on the copy, which refuse every other policy error.
fn bind_casework_run_issuer(plan: &Plan, project: &Path, bound: &Path) -> Result<()> {
    let mut document = checked_casework_run_issuer(plan, project)?;
    let (binding, guard) = run_issuer_binding(plan)?;
    ensure!(
        is_loopback_run_issuer(&plan.issuer),
        "the run issuer {} is not a loopback URL of the form http://127.0.0.1:<port>",
        plan.issuer
    );
    let entry = &mut document["trustedProducers"][&binding.producer];
    entry["issuer"] = json!(plan.issuer);
    if guard.initiator.is_some() {
        entry["trustedInitiatorIssuer"] = json!(plan.issuer);
    }
    copy_project(project, bound)?;
    write_private(
        &bound.join("casework.yaml"),
        serde_norway::to_string(&document)?.as_bytes(),
    )
}

fn run_issuer_binding(plan: &Plan) -> Result<(&BregReviewAuthority, &RunIssuerBinding)> {
    let binding = plan
        .bindings
        .breg_review_authority
        .as_ref()
        .context("the run issuer binding needs a review authority binding")?;
    let guard = binding
        .run_issuer_binding
        .as_ref()
        .context("the review authority binding has no run issuer binding")?;
    Ok((binding, guard))
}

/// Reads the Casework project's `casework.yaml` and refuses, at the dev.yaml
/// pointer, a run issuer binding that does not match the trusted producer it
/// names. `check` runs this before any product starts; `start` runs it again
/// before binding the run issuer.
fn checked_casework_run_issuer(plan: &Plan, project: &Path) -> Result<Value> {
    let (binding, guard) = run_issuer_binding(plan)?;
    let refuse = |pointer: String, message: &str, action: &str| {
        anyhow::Error::from(plan::SemanticRefusal::new(&pointer, message, action))
    };
    let identity = &plan.people[&binding.identity];
    let grant = &identity.grants[&Product::Casework];
    let person = format!(
        "/people/{}",
        registry_platform_yaml::escape_pointer_segment(&binding.identity)
    );

    let source = project.join("casework.yaml");
    let bytes = fs::read(&source).with_context(|| format!("cannot read {}", source.display()))?;
    let document = registry_platform_yaml::Reader::new(source.display().to_string())
        .scan(&bytes)
        .map_err(|_| anyhow::anyhow!("{} is not valid YAML", source.display()))?
        .with_context(|| format!("{} is empty", source.display()))?
        .to_json_value();
    let producer = document["trustedProducers"][&binding.producer].clone();
    if !producer.is_object() {
        return Err(refuse(
            "/bindings/bregReviewAuthority/producer".to_owned(),
            "The Casework project has no trusted producer with this ID.",
            "Set producer to a trustedProducers entry in casework.yaml.",
        ));
    }
    let text = |member: &str| producer[member].as_str().unwrap_or_default();
    let expected = &guard.producer;
    if text("issuer") != expected.expected_issuer {
        return Err(refuse(
            format!("{RUN_ISSUER_BINDING}/producer/expectedIssuer"),
            "The producer's issuer in casework.yaml is not the issuer the binding expects.",
            "Set expectedIssuer to the issuer the Casework project pins for this producer.",
        ));
    }
    if text("profile") != expected.expected_profile || grant.profile != expected.expected_profile {
        return Err(refuse(
            format!("{RUN_ISSUER_BINDING}/producer/expectedProfile"),
            "The producer's profile in casework.yaml, the binding and the identity's Casework grant must be the same profile.",
            "Set expectedProfile and the identity's Casework grant profile to the producer's profile.",
        ));
    }
    if text("subject") != expected.expected_subject || identity.subject != expected.expected_subject
    {
        return Err(refuse(
            format!("{RUN_ISSUER_BINDING}/producer/expectedSubject"),
            "The producer's subject in casework.yaml, the binding and the identity's subject must be the same subject.",
            "Set expectedSubject and the identity's subject to the producer's subject.",
        ));
    }
    let required = document["accessProfiles"][&expected.expected_profile]["requiredScopes"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if let Some(missing) = required
        .iter()
        .filter_map(Value::as_str)
        .find(|scope| !grant.scopes.iter().any(|granted| granted == scope))
    {
        return Err(refuse(
            format!("{person}/grants/casework/scopes"),
            &format!("The identity's Casework grant lacks the scope {missing} that the producer's profile requires."),
            "Add the scope to the grant.",
        ));
    }
    if let Some(initiator) = &guard.initiator {
        if producer["trustedInitiatorIssuer"].as_str() != Some(initiator.expected_issuer.as_str()) {
            return Err(refuse(
                format!("{RUN_ISSUER_BINDING}/initiator/expectedIssuer"),
                "The producer's trustedInitiatorIssuer in casework.yaml is not the issuer the binding expects.",
                "Set expectedIssuer to the trustedInitiatorIssuer the Casework project pins for this producer.",
            ));
        }
    }
    Ok(document)
}

/// Only a reserved loopback run URL is bound, never a remote issuer.
pub(super) fn is_loopback_run_issuer(issuer: &str) -> bool {
    issuer
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| issuer.strip_prefix("http://[::1]:"))
        .map(|rest| rest.strip_suffix('/').unwrap_or(rest))
        .is_some_and(|port| {
            !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|port| port > 1)
        })
}

fn has_run_source(plan: &Plan) -> bool {
    plan.bindings.binds_run_issuer()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::{Bindings, BregReviewAuthority, CaseworkContextProvider};
    use std::{
        io::{BufRead, BufReader},
        os::unix::fs::PermissionsExt,
        sync::mpsc,
    };

    #[test]
    fn the_project_copy_is_private_to_the_owner() {
        let scratch = tempfile::tempdir().unwrap();
        let source = scratch.path().join("source");
        fs::create_dir_all(source.join("keys")).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(source.join("keys"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(source.join("keys/signing.key"), "secret").unwrap();
        fs::set_permissions(
            source.join("keys/signing.key"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        fs::write(source.join("run.sh"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(source.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        let target = scratch.path().join("copy");
        copy_project(&source, &target).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&target), 0o700);
        assert_eq!(mode(&target.join("keys")), 0o700);
        assert_eq!(mode(&target.join("keys/signing.key")), 0o600);
        assert_eq!(mode(&target.join("run.sh")), 0o700);
    }

    #[test]
    fn breg_validation_refusal_carries_the_tool_diagnostics() {
        let invalid = InvalidBregProject {
            findings: "registry.yaml project.apiVersion[1]: the document ends".to_owned(),
            actions: "correct-source".to_owned(),
        };
        let refusal = breg_validation_refusal("/products/0/project", &invalid).to_string();
        assert!(
            refusal.contains("registry.yaml project.apiVersion[1]: the document ends"),
            "the refusal must name the file: {refusal}"
        );
        assert!(
            !refusal.contains(".."),
            "each sentence ends once: {refusal}"
        );
        assert!(
            !refusal.contains("rstack breg check"),
            "the refusal must not send the adopter to a second command"
        );
    }

    #[test]
    fn casework_findings_keep_the_owning_tool_error_diagnostics() {
        let report = json!({"diagnostics":[
            {"severity":"error","path":"casework.yaml#/forms/0","message":"unknown form field"},
            {"severity":"warning","path":"casework.yaml#/x","message":"ignored warning"}]});
        assert_eq!(
            casework_findings(&report),
            "casework.yaml#/forms/0: unknown form field"
        );
    }

    #[test]
    fn a_failed_schema_test_keeps_the_tools_report_and_its_codes() {
        use std::io::Write as _;
        use std::os::unix::process::ExitStatusExt as _;
        let scratch = tempfile::tempdir().unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let root = scratch.path().join(id);
        private_directory(&root).unwrap();
        drop(open_log(&root, "breg-test").unwrap());
        let mut output = tempfile::tempfile_in(&root).unwrap();
        let report = br#"{"ok":false,"command":"test","diagnostics":[{"severity":"error","code":"test.step.failed","path":"journeys[0].steps[0]","message":"the tool's own words"}]}"#;
        output.write_all(report).unwrap();
        let error = logged_tool_result(
            ExitStatus::from_raw(256),
            &mut output,
            &root,
            ("breg", "test"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("test.step.failed"));
        let path = root.join("logs/breg-test-report.json");
        assert!(fs::metadata(&path).unwrap().permissions().mode() & 0o777 == 0o600);
        let kept = crate::keep_logs(&root, id).unwrap().unwrap();
        fs::remove_dir(&root).unwrap();
        assert_eq!(
            fs::read(kept.join("breg-test-report.json")).unwrap(),
            report
        );
    }

    #[test]
    fn minimal_schema_tokens_preserve_exact_client_and_fixture_claims() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        // The shapes a BReg development project declares for its clients and
        // journey steps, written out so the test needs no product library.
        let clients = json!({"clients": [{
            "id": "registry-editor",
            "accessProfiles": ["editor"],
            "scopes": ["registry.read", "registry.write"],
            "claims": {"registry_principal": "editor-1", "registry_purpose": "intake"}
        }]});
        let fixtures = json!({"journeys": [{"steps": [{
            "accessProfile": "editor",
            "claims": {
                "principal": "editor-1",
                "purpose": "intake",
                "directClaims": {"registry_purpose": "intake"},
                "scopes": ["registry.read", "registry.write"]
            }
        }]}]});
        let root = tempfile::tempdir().unwrap();
        let issuer = Issuer::create(root.path()).unwrap();
        let mut input = breg_input(false);
        input.breg_authority.as_mut().unwrap().principal = "registry_principal".into();
        input.breg_authority.as_mut().unwrap().purpose = true;
        for client in clients["clients"].as_array().unwrap() {
            let raw = client["claims"].as_object().unwrap();
            assert!(!raw.contains_key("registry_actor_kind"));
            let mut claims = raw.clone();
            let subject = claims.remove("registry_principal").unwrap();
            let mut person:plan::TestPerson=serde_json::from_value(json!({"subject":subject,"client":client["id"],
                "grants":{"breg":{"profile":client["accessProfiles"][0],"scopes":client["scopes"],"claims":claims}}})).unwrap();
            let payload = |person: &plan::TestPerson| -> Value {
                let token = issuer
                    .token(&input, person, Product::Breg, clock().unwrap() + 300)
                    .unwrap();
                serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(token.split('.').nth(1).unwrap())
                        .unwrap(),
                )
                .unwrap()
            };
            // Reproduce the old test adapter's omission without a product run.
            assert!(payload(&person).get("registry_actor_kind").is_none());
            // Existing dev/config::client_token_claims makes this ordinary
            // machine default explicit; no issuer or verifier default changes.
            person
                .grants
                .get_mut(&Product::Breg)
                .unwrap()
                .claims
                .insert("registry_actor_kind".into(), json!("service"));
            let minted = payload(&person);
            assert!(minted["registry_actor_kind"] == "service");
            let mut expected_names: BTreeSet<_> = raw.keys().map(String::as_str).collect();
            expected_names.extend([
                "registry_actor_kind",
                "iss",
                "aud",
                "sub",
                "client_id",
                "scope",
                "iat",
                "exp",
                "jti",
            ]);
            assert!(
                minted
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
                    == expected_names
            );
            assert!(raw
                .iter()
                .all(|(name, value)| minted.get(name) == Some(value)));
            assert!(minted["sub"] == subject && minted["client_id"] == client["id"]);
            assert!(
                minted["iss"] == input.plan.issuer
                    && minted["aud"] == input.plan.product(Product::Breg).audience
            );
            let scopes: BTreeSet<_> = minted["scope"].as_str().unwrap().split(' ').collect();
            let registered: BTreeSet<_> = client["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap())
                .collect();
            assert!(scopes == registered);
            for step in fixtures["journeys"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|j| j["steps"].as_array().unwrap())
                .filter(|step| step["claims"]["principal"] == subject)
            {
                assert!(person.grants[&Product::Breg].profile == step["accessProfile"]);
                assert!(minted["registry_purpose"] == step["claims"]["purpose"]);
                assert!(step["claims"]["directClaims"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .all(|(name, value)| minted.get(name) == Some(value)));
                let expected: BTreeSet<_> = step["claims"]["scopes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s.as_str().unwrap())
                    .collect();
                assert!(scopes == expected);
            }
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
            "scenarioFile": "tests/scenarios.yaml"
        }))
        .unwrap()
    }

    #[test]
    fn breg_authority_restrictions_are_typed_and_located() {
        let plan = authority_plan(
            json!({"registry_principal": "private-claim-marker"}),
            json!({}),
            false,
        );
        let error = breg_principal(&plan, &BTreeSet::from(["registry_principal".to_owned()]))
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
                run_issuer_binding: None,
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
        let authorities = BTreeSet::from(["review-authority".to_owned()]);
        let actions = BTreeSet::from(["review-action".to_owned()]);
        let facts = |review_authorities: &BTreeSet<String>, actions: &BTreeSet<String>| BregFacts {
            review_authorities: review_authorities.clone(),
            actions: actions.clone(),
            ..BregFacts::default()
        };
        validate_breg_binding_ids(&bindings, &facts(&authorities, &actions)).unwrap();

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
            let error = validate_breg_binding_ids(&bindings, &facts(&authorities, &actions))
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
    fn run_issuer_runtime_configs_keep_authentication_and_both_bindings_on_the_allocated_url() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance/reviewed-evidence-journey")
            .canonicalize()
            .unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let terminate = AtomicBool::new(false);
        let mut input = breg_input(false);
        input.plan = plan::load(&fixture).unwrap().plan;
        let fixed_issuer = input.plan.issuer.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let allocated_issuer = format!("http://{}", listener.local_addr().unwrap());
        for (name, expected, application) in [
            ("fixed", fixed_issuer.clone(), false),
            ("browser", allocated_issuer.clone(), true),
            ("product-only", allocated_issuer, false),
        ] {
            let root = scratch.path().join(name);
            super::super::private_directory(&root).unwrap();
            let mut captured: RunInput =
                serde_json::from_value(serde_json::to_value(&input).unwrap()).unwrap();
            captured.plan.issuer = expected.clone();
            if expected.starts_with("http:") {
                captured.plan.bindings.breg_review_authority.as_mut().unwrap().run_issuer_binding=Some(serde_json::from_value(json!({"producer":{"expectedIssuer":fixed_issuer,"expectedProfile":"requester","expectedSubject":"producer"}})).unwrap());
            }
            if application {
                captured.plan.application = Some(serde_json::from_value(json!({
                    "client": "browser-client", "callbackPath": "/callback", "healthPath": "/health",
                    "entry": "dist/main.js", "prepare": "dist/prepare.js", "checker": "dist/check.js",
                    "deployment": "deployment.json", "configSchema": "example/host-run/v1",
                    "configEnvironment": "HOST_CONFIG", "prepareVersion": "example-prepare 1.0"
                })).unwrap());
            }
            let captured = Arc::new(captured);
            let issuer = Arc::new(Issuer::create(&root).unwrap());
            let origins = BTreeMap::from([
                (Product::Breg, "http://127.0.0.1:31001".to_owned()),
                (Product::Casework, "http://127.0.0.1:31002".to_owned()),
            ]);
            let mut runner = ProductRunner::new(captured.clone(), &root, &terminate).unwrap();
            runner.bindings =
                Some(RuntimeBindings::prepare(&root, captured, issuer, &origins).unwrap());
            let (breg, _) = breg_config(&runner, &root, "breg");
            let path = runner
                .config(
                    Product::Casework,
                    "casework",
                    "127.0.0.1:0",
                    &root.join("casework-package"),
                    DatabaseUrls {
                        runtime: "postgresql://runtime:password@127.0.0.1:5432/run".to_owned(),
                        migration: "postgresql://migration:password@127.0.0.1:5432/run".to_owned(),
                    },
                )
                .unwrap();
            let casework: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            let breg_issuer = &breg["authentication"]["oidc"]["issuers"]["main"];
            assert_eq!(breg_issuer["issuer"], expected);
            assert_eq!(
                breg["authentication"]["oidc"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .collect::<Vec<_>>(),
                ["issuers"]
            );
            let casework_issuer = &casework["authentication"]["oidc"]["issuers"]["main"];
            assert_eq!(casework_issuer["issuer"], expected);
            for oidc in [breg_issuer, casework_issuer] {
                assert_eq!(oidc["jwksSource"]["type"], "test-issuer");
            }
            for config in [&breg, &casework] {
                assert_eq!(config["audit"]["hashKeyCustody"], "development-generated");
            }
            assert_eq!(casework["listener"]["tlsTermination"], "loopback-plaintext");
            if !application {
                for clients in [
                    &breg_issuer["allowedClients"],
                    &casework_issuer["allowedClients"],
                ] {
                    assert!(!clients
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|client| client == "browser-client"));
                }
                assert_eq!(breg_issuer["maximumTokenLifetimeSeconds"], 3600);
            }

            assert_eq!(
                breg["reviewAuthorities"]["casework"]["privateKeyJwt"]["assertionAudience"],
                expected
            );
            assert_eq!(
                casework["contextProviders"]["registry"]["clientAssertionAudience"],
                expected
            );
            assert_eq!(
                breg["reviewAuthorities"]["casework"]["privateKeyJwt"]["resource"],
                "urn:journey:casework"
            );
            assert_eq!(
                casework["contextProviders"]["registry"]["resource"],
                "urn:journey:breg"
            );
        }
    }

    #[test]
    fn breg_package_arguments_declare_development() {
        let args = breg_package_arguments(
            Path::new("project"),
            Path::new("receipt.json"),
            Path::new("build"),
        );
        assert!(args
            .windows(2)
            .any(|pair| pair[0] == "--posture" && pair[1] == "development"));
        assert!(!args.contains(&std::ffi::OsStr::new("--local")));
    }

    #[test]
    fn direct_product_tools_declare_development() {
        use registry_platform_config::{DEVELOPMENT, POSTURE_ENV};
        use std::ffi::OsStr;

        let command = child_command(Path::new("/bin/sh"));
        assert!(command
            .get_envs()
            .any(|(key, value)| key == POSTURE_ENV && value == Some(OsStr::new(DEVELOPMENT))));
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
            "scenarioFile": "tests/scenarios.yaml"
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
        assert_eq!(
            rendered["authentication"]["oidc"]["issuers"]["main"]["maximumTokenLifetimeSeconds"],
            3600
        );
        assert_eq!(written, rendered);
        assert_eq!(
            written["authentication"]["oidc"]["issuers"]["main"]["allowedClients"],
            json!(["reviewer-client"])
        );
        assert!(!written.to_string().contains("password"), "{written}");
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
    fn run_package_receipts_are_exact_and_a_write_failure_stops_the_step() {
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let mut output = tempfile::tempfile().unwrap();
        let bytes=br#"{"ok":true,"command":"package","status":"complete","kind":"CaseworkReport","apiVersion":"id.registrystack.org/formats/casework/report/v1alpha2","packageDigest":"sha256:synthetic"}"#;
        output.write_all(bytes).unwrap();
        retain_tool_receipt(&mut output, root.path(), "casework", "package").unwrap();
        assert_eq!(
            fs::read(root.path().join("casework-package-receipt.json")).unwrap(),
            bytes
        );
        assert!(retain_tool_receipt(&mut output, root.path(), "casework", "apply").is_err());
        let blocked = tempfile::tempdir().unwrap();
        fs::create_dir(blocked.path().join("casework-package-receipt.json")).unwrap();
        assert!(retain_tool_receipt(&mut output, blocked.path(), "casework", "package").is_err());
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
    fn spawned_processes_record_products_and_application_groups() {
        let scratch = tempfile::tempdir().unwrap();
        write_processes(
            scratch.path(),
            &[
                (RuntimeKind::Product(Product::Breg), 4242),
                (RuntimeKind::Product(Product::Casework), 4343),
                (RuntimeKind::Application, 4444),
            ],
        )
        .unwrap();
        let path = scratch.path().join("processes.json");
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
            json!([
                {"product": "breg", "pid": 4242, "pgid": 4242},
                {"product": "casework", "pid": 4343, "pgid": 4343},
                {"application": "application", "pid": 4444, "pgid": 4444}
            ])
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn application_health_path_cannot_change_request_authority() {
        assert!(valid_health_path("/health"));
        for path in [
            "//other.invalid",
            "/\\other.invalid",
            "/health?next=other",
            "/health#part",
            "health",
        ] {
            assert!(!valid_health_path(path), "{path}");
        }
    }

    #[test]
    fn application_run_input_binds_each_service_and_references_secrets() {
        let mut input = breg_input(false);
        let mut plan = serde_json::to_value(&input.plan).unwrap();
        plan["issuer"] = json!("http://127.0.0.1:4200");
        plan["application"] = json!({
            "client": "browser-client", "callbackPath": "/callback", "healthPath": "/health",
            "entry": "dist/main.js", "prepare": "dist/prepare.js", "checker": "dist/check.js",
            "deployment": "deployment.json", "configSchema": "example/host-run/v1",
            "configEnvironment": "HOST_CONFIG", "prepareVersion": "example-prepare 1.0"
        });
        input.plan = serde_json::from_value(plan.clone()).unwrap();
        let urls = BTreeMap::from([(Product::Breg, "http://127.0.0.1:4201".to_owned())]);
        let run = application_run_input(
            &input,
            &urls,
            "http://127.0.0.1:4202",
            4202,
            Path::new("/private/client-secret"),
            None,
        );
        assert_eq!(run["schema"], "example/host-run/v1");
        assert_eq!(run["origin"], "http://127.0.0.1:4202");
        assert_eq!(run["port"], 4202);
        assert_eq!(run["oidc"]["issuer"], "http://127.0.0.1:4200");
        assert_eq!(run["oidc"]["accessTokenSigningAlgorithm"], "ES256");
        assert_eq!(run["oidc"]["clientSecretFile"], "/private/client-secret");
        assert!(run["oidc"].get("recoveryKeyFile").is_none());
        assert!(run["oidc"].get("separateResourceGrants").is_none());
        assert_eq!(run["breg"]["audience"], "registry");
        assert!(run.get("casework").is_none());
        assert!(!run.to_string().contains("browser-client"));

        plan["products"].as_array_mut().unwrap().push(json!({
            "product": "casework", "project": "casework", "audience": "review"
        }));
        plan["application"]["caseworkSourceCredentialRoles"] = json!(["reviewer"]);
        input.plan = serde_json::from_value(plan).unwrap();
        let urls = BTreeMap::from([
            (Product::Breg, "http://127.0.0.1:4201".to_owned()),
            (Product::Casework, "http://127.0.0.1:4203".to_owned()),
        ]);
        let run = application_run_input(
            &input,
            &urls,
            "http://127.0.0.1:4202",
            4202,
            Path::new("/private/client-secret"),
            Some(Path::new("/private/recovery-key")),
        );
        assert_eq!(run["casework"]["baseUrl"], "http://127.0.0.1:4203");
        assert_eq!(run["casework"]["audience"], "review");
        assert_eq!(run["oidc"]["recoveryKeyFile"], "/private/recovery-key");
        assert_eq!(run["oidc"]["separateResourceGrants"], true);
        assert_eq!(
            run["casework"]["sourceCredentialRoles"],
            json!(["reviewer"])
        );
    }

    #[test]
    fn built_application_file_cannot_escape_its_root_through_a_symlink() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(root.path().join("entry.js"), "entry").unwrap();
        fs::write(outside.path().join("other.js"), "other").unwrap();
        assert_eq!(
            application_file(root.path(), Path::new("entry.js")).unwrap(),
            root.path().join("entry.js").canonicalize().unwrap()
        );
        std::os::unix::fs::symlink(
            outside.path().join("other.js"),
            root.path().join("linked.js"),
        )
        .unwrap();
        assert!(application_file(root.path(), Path::new("linked.js")).is_err());
    }

    fn fixture_node(root: &Path, node_version: &str) -> (PathBuf, ApplicationPlan) {
        for name in ["entry.js", "prepare.js", "check.js"] {
            fs::write(root.join(name), "fixture").unwrap();
        }
        let node = root.join("node");
        write_private(
            &node,
            format!("#!/usr/bin/env bash\nset -euo pipefail\nif [[ $1 == --version ]]; then\n  printf '{node_version}\\n'\nelse\n  printf 'fixture-prepare 1.0\\n'\nfi\n").as_bytes(),
        )
        .unwrap();
        fs::set_permissions(&node, fs::Permissions::from_mode(0o700)).unwrap();
        let plan: ApplicationPlan = serde_json::from_value(json!({
            "client": "browser-client", "callbackPath": "/callback",
            "healthPath": "/health", "entry": "entry.js", "prepare": "prepare.js",
            "checker": "check.js", "deployment": "deployment.json",
            "configSchema": "fixture/run/v1", "configEnvironment": "FIXTURE_CONFIG",
            "prepareVersion": "fixture-prepare 1.0"
        }))
        .unwrap();
        (node, plan)
    }

    #[test]
    fn application_preflight_checks_the_node_floor_and_warns_on_a_prepare_version_change() {
        let root = tempfile::tempdir().unwrap();
        let (node, mut plan) = fixture_node(root.path(), "v24.11.0");
        let preflight = preflight_application_with_node(root.path(), &plan, &node).unwrap();
        assert_eq!(preflight.node, node.canonicalize().unwrap());
        assert!(preflight.warnings.is_empty(), "{:?}", preflight.warnings);
        plan.prepare_version = "fixture-prepare 2.0".to_owned();
        let preflight = preflight_application_with_node(root.path(), &plan, &node).unwrap();
        assert_eq!(preflight.warnings.len(), 1);
        assert!(
            preflight.warnings[0].contains("/application/prepareVersion")
                && preflight.warnings[0].contains("fixture-prepare 1.0"),
            "{:?}",
            preflight.warnings
        );
    }

    #[test]
    fn node_newer_than_24_is_accepted_with_a_warning() {
        let root = tempfile::tempdir().unwrap();
        let (node, plan) = fixture_node(root.path(), "v26.1.0");
        let preflight = preflight_application_with_node(root.path(), &plan, &node).unwrap();
        assert_eq!(preflight.warnings.len(), 1);
        assert!(preflight.warnings[0].contains("v26.1.0"));
    }

    #[test]
    fn the_schema_credentials_document_matches_the_published_schema() {
        let schema: Value = serde_json::from_slice(
            &fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../products/breg/generated/tools/schema-test-credentials.v1.schema.json",
            ))
            .unwrap(),
        )
        .unwrap();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        let document = serde_json::to_value(SchemaCredentials {
            api_version: SCHEMA_CREDENTIALS_API_VERSION,
            kind: SCHEMA_CREDENTIALS_KIND,
            bindings: vec![SchemaCredentialBinding {
                journey_id: "smoke",
                step_id: "read",
                credential: SchemaCredential {
                    kind: "bearer",
                    token_ref: secret_ref("schema-token-0"),
                },
            }],
        })
        .unwrap();
        let errors: Vec<_> = validator
            .validate(&document)
            .err()
            .into_iter()
            .flatten()
            .map(|error| format!("{} at {}", error.instance_path, error.schema_path))
            .collect();
        assert!(errors.is_empty(), "{errors:?}");
        let mut wrong = document;
        wrong["kind"] = json!("Other");
        assert!(validator.validate(&wrong).is_err());
    }

    #[test]
    fn the_run_issuer_is_bound_only_when_it_is_a_loopback_url() {
        assert!(is_loopback_run_issuer("http://127.0.0.1:41000/"));
        assert!(is_loopback_run_issuer("http://127.0.0.1:41000"));
        for refused in [
            "http://127.0.0.1:1/",
            "https://127.0.0.1:41000/",
            "http://localhost:41000/",
            "http://127.0.0.1:41000/x/",
            "http://127.0.0.1:abc/",
        ] {
            assert!(!is_loopback_run_issuer(refused), "{refused}");
        }
    }

    const PRODUCER_ISSUER: &str = "https://issuer.example.invalid/";

    /// A dev.yaml plan and a Casework project document that agree on one
    /// producer with an initiator pin. Each case breaks one agreement.
    fn run_issuer_fixture(with_initiator: bool) -> (Value, Value) {
        let mut guard = json!({"producer": {
            "expectedIssuer": PRODUCER_ISSUER,
            "expectedProfile": "review-producer",
            "expectedSubject": "breg-producer"
        }});
        if with_initiator {
            guard["initiator"] = json!({"expectedIssuer": "https://initiator.example.invalid/", "trust": "run-test-people"});
        }
        let plan = json!({
            "issuer": "http://127.0.0.1:41000/",
            "products": [
                {"product": "breg", "project": "breg", "audience": "registry"},
                {"product": "casework", "project": "casework", "audience": "review"}
            ],
            "people": {"authority": {
                "subject": "breg-producer", "client": "authority-client",
                "grants": {"casework": {
                    "profile": "review-producer", "scopes": ["review.write"]
                }}
            }},
            "scenarioFile": "tests/scenarios.yaml",
            "bindings": {"bregReviewAuthority": {
                "id": "authority", "producer": "producer", "identity": "authority",
                "runIssuerBinding": guard
            }}
        });
        let mut producer = json!({
            "issuer": PRODUCER_ISSUER,
            "profile": "review-producer",
            "subject": "breg-producer",
            "audience": "unrelated-member"
        });
        if with_initiator {
            producer["trustedInitiatorIssuer"] = json!("https://initiator.example.invalid/");
        }
        let casework = json!({
            "name": "synthetic-project",
            "accessProfiles": {"review-producer": {"requiredScopes": ["review.write"]}},
            "trustedProducers": {
                "producer": producer,
                "other-producer": {"issuer": "https://other.example.invalid/"}
            }
        });
        (plan, casework)
    }

    fn write_casework_project(root: &Path, casework: &Value) -> PathBuf {
        let project = root.join("project");
        fs::create_dir(&project).unwrap();
        fs::write(
            project.join("casework.yaml"),
            serde_norway::to_string(casework).unwrap(),
        )
        .unwrap();
        fs::write(project.join("notes.txt"), "kept as written").unwrap();
        project
    }

    #[test]
    fn casework_run_issuer_binding_refuses_each_mismatch_at_its_pointer() {
        type Break = fn(&mut Value, &mut Value);
        const BINDING: &str = "/bindings/bregReviewAuthority/runIssuerBinding";
        let cases: [(&str, String, Break); 9] = [
            (
                "the producer is not in casework.yaml",
                "/bindings/bregReviewAuthority/producer".to_owned(),
                |_, casework| {
                    casework["trustedProducers"]
                        .as_object_mut()
                        .unwrap()
                        .remove("producer");
                },
            ),
            (
                "the producer issuer differs from the binding",
                format!("{BINDING}/producer/expectedIssuer"),
                |_, casework| {
                    casework["trustedProducers"]["producer"]["issuer"] =
                        json!("https://elsewhere.example.invalid/");
                },
            ),
            (
                "casework.yaml profile differs from the binding",
                format!("{BINDING}/producer/expectedProfile"),
                |_, casework| {
                    casework["trustedProducers"]["producer"]["profile"] = json!("other-profile");
                },
            ),
            (
                "the grant profile differs from the binding",
                format!("{BINDING}/producer/expectedProfile"),
                |plan, _| {
                    plan["people"]["authority"]["grants"]["casework"]["profile"] =
                        json!("other-profile");
                },
            ),
            (
                "casework.yaml subject differs from the binding",
                format!("{BINDING}/producer/expectedSubject"),
                |_, casework| {
                    casework["trustedProducers"]["producer"]["subject"] = json!("other-subject");
                },
            ),
            (
                "the identity subject differs from the binding",
                format!("{BINDING}/producer/expectedSubject"),
                |plan, _| {
                    plan["people"]["authority"]["subject"] = json!("not-the-producer");
                },
            ),
            (
                "a required scope is missing from the grant",
                "/people/authority/grants/casework/scopes".to_owned(),
                |plan, _| {
                    plan["people"]["authority"]["grants"]["casework"]["scopes"] =
                        json!(["review.read"]);
                },
            ),
            (
                "the producer has no initiator pin",
                format!("{BINDING}/initiator/expectedIssuer"),
                |_, casework| {
                    casework["trustedProducers"]["producer"]
                        .as_object_mut()
                        .unwrap()
                        .remove("trustedInitiatorIssuer");
                },
            ),
            (
                "the initiator pin differs from the binding",
                format!("{BINDING}/initiator/expectedIssuer"),
                |_, casework| {
                    casework["trustedProducers"]["producer"]["trustedInitiatorIssuer"] =
                        json!("https://elsewhere.example.invalid/");
                },
            ),
        ];
        let root = tempfile::tempdir().unwrap();
        for (index, (name, pointer, break_it)) in cases.into_iter().enumerate() {
            let (mut plan, mut casework) = run_issuer_fixture(true);
            break_it(&mut plan, &mut casework);
            let case_root = root.path().join(index.to_string());
            fs::create_dir(&case_root).unwrap();
            let project = write_casework_project(&case_root, &casework);
            let plan: Plan = serde_json::from_value(plan).unwrap();
            let error = checked_casework_run_issuer(&plan, &project).unwrap_err();
            let refusal = error
                .downcast_ref::<plan::SemanticRefusal>()
                .unwrap_or_else(|| panic!("{name}: not a semantic refusal: {error}"));
            assert!(
                refusal
                    .to_string()
                    .starts_with(&format!("dev.yaml {pointer}: ")),
                "{name}: {refusal}"
            );
        }
        let (plan, casework) = run_issuer_fixture(true);
        let project = write_casework_project(root.path(), &casework);
        let plan: Plan = serde_json::from_value(plan).unwrap();
        checked_casework_run_issuer(&plan, &project).unwrap();
    }

    #[test]
    fn binding_the_run_issuer_changes_only_the_producer_issuer_members() {
        for with_initiator in [false, true] {
            let (plan, casework) = run_issuer_fixture(with_initiator);
            let plan: Plan = serde_json::from_value(plan).unwrap();
            let root = tempfile::tempdir().unwrap();
            let project = write_casework_project(root.path(), &casework);
            let before = fs::read(project.join("casework.yaml")).unwrap();
            let bound = root.path().join("bound");
            bind_casework_run_issuer(&plan, &project, &bound).unwrap();

            assert_eq!(fs::read(project.join("casework.yaml")).unwrap(), before);
            assert_eq!(
                fs::read(bound.join("notes.txt")).unwrap(),
                b"kept as written"
            );
            let parse = |path: PathBuf| -> Value {
                registry_platform_yaml::Reader::new(path.display().to_string())
                    .scan(&fs::read(&path).unwrap())
                    .unwrap()
                    .unwrap()
                    .to_json_value()
            };
            let source = parse(project.join("casework.yaml"));
            let mut expected = source.clone();
            expected["trustedProducers"]["producer"]["issuer"] = json!(plan.issuer);
            if with_initiator {
                expected["trustedProducers"]["producer"]["trustedInitiatorIssuer"] =
                    json!(plan.issuer);
            }
            assert_ne!(expected, source);
            assert_eq!(parse(bound.join("casework.yaml")), expected);
        }
    }

    #[test]
    fn node_older_than_24_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let (node, plan) = fixture_node(root.path(), "v22.4.0");
        let error = preflight_application_with_node(root.path(), &plan, &node)
            .err()
            .unwrap();
        assert!(error.to_string().contains("Node 24 or newer"), "{error}");
    }

    const APPLICATION_FIXTURE_PORT: &str = "APPLICATION_FIXTURE_PORT";
    const APPLICATION_FIXTURE_EXIT: &str = "APPLICATION_FIXTURE_EXIT";
    const APPLICATION_FIXTURE_IGNORE_TERM: &str = "APPLICATION_FIXTURE_IGNORE_TERM";

    /// The guarded child used by `a_guarded_application_exit_stops_restarts_and_reaps`.
    /// An ordinary unit-test run has no fixture environment and returns at once.
    #[test]
    fn guarded_application_fixture() {
        let Some(port) = std::env::var_os(APPLICATION_FIXTURE_PORT) else {
            return;
        };
        let term_received = Arc::new(AtomicBool::new(false));
        if std::env::var_os(APPLICATION_FIXTURE_IGNORE_TERM).is_some() {
            signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term_received))
                .unwrap();
        }
        let exit = PathBuf::from(std::env::var_os(APPLICATION_FIXTURE_EXIT).unwrap());
        let listener = TcpListener::bind((
            Ipv4Addr::LOCALHOST,
            port.to_string_lossy().parse::<u16>().unwrap(),
        ))
        .unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            request.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
        }
        use std::io::Write as _;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        while !exit.exists() {
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn application_fixture_launch(
        root: &Path,
        exit: &Path,
        ignore_term: bool,
    ) -> (ApplicationLaunch, u16) {
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        let mut environment = BTreeMap::from([
            (APPLICATION_FIXTURE_PORT.to_owned(), port.to_string()),
            (
                APPLICATION_FIXTURE_EXIT.to_owned(),
                exit.to_string_lossy().into_owned(),
            ),
        ]);
        if ignore_term {
            environment.insert(APPLICATION_FIXTURE_IGNORE_TERM.to_owned(), "1".to_owned());
        }
        for name in ["DYLD_FALLBACK_LIBRARY_PATH", "LD_LIBRARY_PATH"] {
            if let Ok(value) = std::env::var(name) {
                environment.insert(name.to_owned(), value);
            }
        }
        (
            ApplicationLaunch {
                program: std::env::current_exe().unwrap(),
                arguments: vec![
                    "products::tests::guarded_application_fixture".into(),
                    "--exact".into(),
                    "--nocapture".into(),
                ],
                workdir: root.to_path_buf(),
                environment,
                reservation,
                health_path: "/health".to_owned(),
            },
            port,
        )
    }

    #[test]
    fn a_guarded_application_exit_stops_restarts_and_reaps() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("run");
        super::super::private_directory(&root).unwrap();
        let terminate = AtomicBool::new(false);
        let mut runner =
            ProductRunner::new(Arc::new(breg_input(false)), &root, &terminate).unwrap();
        let first_exit = root.join("application-exit-first");
        let (first_launch, first_port) = application_fixture_launch(&root, &first_exit, false);

        let origin = runner.start_application(first_launch).unwrap();
        assert_eq!(origin, format!("http://127.0.0.1:{first_port}"));
        assert!(runner.services_alive().unwrap());

        fs::write(&first_exit, "stop").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while runner.services_alive().unwrap() {
            assert!(
                Instant::now() < deadline,
                "the guarded application did not exit"
            );
            thread::sleep(POLL);
        }

        runner.stop().unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(root.join("processes.json")).unwrap())
                .unwrap(),
            json!([])
        );
        assert!(guard::incomplete_launches(&root).unwrap().is_empty());
        let first_states: Vec<_> = fs::read_dir(root.join(guard::DIRECTORY))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "state")
            })
            .collect();
        assert_eq!(first_states.len(), 1, "{first_states:?}");
        assert_eq!(fs::read(&first_states[0]).unwrap(), b"complete\n");

        let second_exit = root.join("application-exit-second");
        let (second_launch, second_port) = application_fixture_launch(&root, &second_exit, true);
        let origin = runner.start_application(second_launch).unwrap();
        assert_eq!(origin, format!("http://127.0.0.1:{second_port}"));
        assert!(runner.services_alive().unwrap());

        let stop_started = Instant::now();
        runner.stop().unwrap();
        let stop_elapsed = stop_started.elapsed();
        assert!(
            stop_elapsed >= Duration::from_secs(2) && stop_elapsed < Duration::from_secs(10),
            "TERM-ignoring application stop took {stop_elapsed:?}"
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(root.join("processes.json")).unwrap())
                .unwrap(),
            json!([])
        );
        assert!(guard::incomplete_launches(&root).unwrap().is_empty());
        let states: Vec<_> = fs::read_dir(root.join(guard::DIRECTORY))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "state")
            })
            .collect();
        assert_eq!(states.len(), 2, "{states:?}");
        assert!(
            states
                .iter()
                .all(|state| fs::read(state).unwrap() == b"complete\n"),
            "{states:?}"
        );
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
        let facts = BregFacts {
            access_profiles: BTreeSet::from(["directory-editor".to_owned()]),
            ..BregFacts::default()
        };
        let people = BTreeMap::from([
            ("editor".to_owned(), breg_person("directory-editor")),
            ("typo".to_owned(), breg_person("directory-edtor")),
        ]);
        let error = check_breg_grants(&facts, &people).unwrap_err().to_string();
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
        check_breg_grants(&facts, &valid).unwrap();
    }

    #[test]
    fn coordinator_retains_an_issuer_port_only_for_local_authenticated_connections() {
        let unauthenticated = json!({"connections": {"target": {}}});
        assert!(!needs_stable_issuer(&unauthenticated, None));
        for field in ["authorization", "observationAuthorization"] {
            let authenticated = json!({"connections": {"target": {(field): {}}}});
            assert!(needs_stable_issuer(&authenticated, None));
            assert!(!needs_stable_issuer(
                &authenticated,
                Some("http://127.0.0.1:41000/keys")
            ));
        }
    }

    #[test]
    fn coordinator_names_the_occupied_issuer_port_and_the_fix() {
        let state = tempfile::tempdir().unwrap();
        let retained = coordinator_issuer_listener(Some(state.path())).unwrap();
        let port = retained.local_addr().unwrap().port();
        let error = coordinator_issuer_listener(Some(state.path()))
            .unwrap_err()
            .to_string();
        assert!(error.contains(&port.to_string()));
        assert!(error.contains("resumable workflow connections") && error.contains("--clean"));
        let ephemeral = coordinator_issuer_listener(None).unwrap();
        assert_ne!(ephemeral.local_addr().unwrap().port(), port);
    }

    #[test]
    fn coordinator_reopens_the_same_managed_development_issuer() {
        let state = tempfile::tempdir().unwrap();
        let listener = coordinator_issuer_listener(Some(state.path())).unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let restarted = coordinator_issuer_listener(Some(state.path())).unwrap();
        assert_eq!(restarted.local_addr().unwrap(), address);
    }

    #[test]
    fn additional_runtime_configuration_uses_run_authority_and_loopback() {
        let root = tempfile::tempdir().unwrap();
        let package = root.path().join("package");
        fs::create_dir(&package).unwrap();
        fs::write(package.join("SHA256SUMS"), b"test checksum file").unwrap();
        fs::write(
            root.path().join("workflow.yaml"),
            "project: {id: standalone}",
        )
        .unwrap();
        fs::write(root.path().join("runtime.yaml"), "connections: {}").unwrap();
        fs::write(
            root.path().join("runtime.example.yaml"),
            "endpoints: [{endpoint: example, baseUrl: 'http://127.0.0.1:1'}]",
        )
        .unwrap();
        let database = DatabaseUrls {
            runtime: "postgresql://runtime@localhost/database".to_owned(),
            migration: "postgresql://migration@localhost/database".to_owned(),
        };
        for product in [
            Product::Scheduling,
            Product::Documents,
            Product::Coordinator,
            Product::Adapter,
            Product::Render,
            Product::Discovery,
        ] {
            let mut input = breg_input(false);
            input.plan.products = serde_json::from_value(json!([{
                "product": product, "project": ".", "audience": "urn:example:local"
            }]))
            .unwrap();
            input.plan.people.clear();
            if product.verifies_tokens() {
                input.plan.people.insert(
                    "tester".to_owned(),
                    serde_json::from_value(json!({
                        "subject": "tester", "client": "console",
                        "grants": {product.name(): {"profile": "console", "scopes": ["read"]}}
                    }))
                    .unwrap(),
                );
            }
            let terminate = AtomicBool::new(false);
            let runner = ProductRunner::new(Arc::new(input), root.path(), &terminate).unwrap();
            let config = runner
                .additional_config(
                    product,
                    root.path(),
                    "127.0.0.1:34567",
                    &package,
                    Some(&database),
                )
                .unwrap();
            // Every product that verifies tokens reads one issuer set: the
            // run issuer is its only entry, and nothing sits at the flat place.
            let (listener, issuer_set) = match product {
                Product::Coordinator => (
                    &config["deployment"]["listener"],
                    &config["deployment"]["authentication"],
                ),
                Product::Adapter => (&config["listener"], &config["oidc"]),
                _ => (&config["listener"], &config["authentication"]["oidc"]),
            };
            let auth = &issuer_set["issuers"]["main"];
            let clients = match product {
                Product::Coordinator => {
                    assert_eq!(auth["allowedClients"], "from-policies");
                    json!(issuer_set["policies"]
                        .as_object()
                        .unwrap()
                        .keys()
                        .collect::<Vec<_>>())
                }
                _ => auth["allowedClients"].clone(),
            };
            match product {
                Product::Scheduling => assert_eq!(config["retention"], json!({})),
                Product::Documents => assert_eq!(config["cleanup"], json!({"erasure": "active"})),
                Product::Adapter => {
                    assert_eq!(config["allowedPrivateCidrs"], json!(["10.0.0.1/32"]))
                }
                Product::Discovery => assert_eq!(listener["requestTimeoutMilliseconds"], 10_000),
                _ => {}
            }
            assert_eq!(listener["bind"], "127.0.0.1:34567");
            if product.verifies_tokens() {
                assert!(issuer_set.get("issuer").is_none(), "{issuer_set}");
                assert!(config.get("allowedClients").is_none(), "{config}");
                assert_eq!(auth["issuer"], runner.input.plan.issuer);
                assert_eq!(auth["audience"], "urn:example:local");
                assert_eq!(auth["jwksSource"]["documentRef"], secret_ref("jwks"));
                assert_eq!(clients, json!(["console"]));
            } else {
                assert!(config.get("authentication").is_none());
            }
        }
    }

    fn breg_input(encrypts_fields: bool) -> RunInput {
        RunInput {
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
            project: PathBuf::from("/tmp/project"),
            application_root: None,
            application_node: None,
            plan: serde_json::from_value(json!({
                "issuer": "https://issuer.example.invalid",
                "products": [{"product": "breg", "project": ".", "audience": "registry"}],
                "people": {"reader": {
                    "subject": "reader", "client": "reader-client",
                    "grants": {"breg": {"profile": "reader", "scopes": []}}
                }},
                "scenarioFile": "tests/scenarios.yaml"
            }))
            .unwrap(),
            scenarios: Vec::new(),
            scenario_digest: String::new(),
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
            binaries: BTreeMap::new(),
            managed_database: false,
            project_key: None,
            clean: false,
        }
    }

    #[test]
    fn breg_config_binds_two_url_hook_destinations_from_the_inventory() {
        let root = tempfile::tempdir().unwrap();
        let tool = root.path().join("bregctl");
        fs::write(&tool, r#"#!/bin/sh
[ "$1 $2 $3 $4" = "--format json explain events" ] || exit 9
cat <<'INVENTORY'
{"ok":true,"explanation":{"deliveries":[
    {"destinationId":"first","classificationCeiling":"public","attemptTimeoutMs":2000,"maximumAttempts":4},
    {"destinationId":"first","classificationCeiling":"restricted","attemptTimeoutMs":3000,"maximumAttempts":2},
    {"destinationId":"second","classificationCeiling":"internal","attemptTimeoutMs":1500,"maximumAttempts":3}
]}}
INVENTORY
"#).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        let mut input = breg_input(false);
        input.binaries.insert(
            Product::Breg,
            crate::Binaries {
                tool: tool.clone(),
                runtime: tool,
            },
        );
        let terminate = AtomicBool::new(false);
        let mut runner = ProductRunner::new(Arc::new(input), root.path(), &terminate).unwrap();
        runner.prepare_breg_hooks(root.path()).unwrap();
        let (config, _) = breg_config(&runner, root.path(), "breg");
        let hooks = config["destinations"]["hooks"].as_object().unwrap();
        assert_eq!(hooks.len(), 2);
        let report = runner.breg_hook_report().unwrap();
        let origin = report["origin"].as_str().unwrap();
        assert!(origin.starts_with("http://127.0.0.1:"));
        assert_eq!(report["receivedUrl"], format!("{origin}/received"));
        for (id, ceiling, timeout, attempts) in [
            ("first", "restricted", 2000, 2),
            ("second", "internal", 1500, 3),
        ] {
            let binding = &hooks[id];
            assert_eq!(binding["origin"], origin);
            assert_eq!(binding["path"], "/events");
            assert_eq!(binding["networkProfile"], "loopback-http");
            assert_eq!(binding["classificationCeiling"], ceiling);
            assert_eq!(
                binding["hmacSha256KeyRef"],
                format!("secret:file/breg-hook-{id}")
            );
            assert!(root.path().join(format!("breg-hook-{id}")).is_file());
            assert_eq!(
                binding["deliveryCeilings"],
                json!({
                    "attemptTimeoutMilliseconds": timeout,
                    "maximumAttempts": attempts,
                })
            );
        }
    }

    #[test]
    fn external_hook_ids_must_match_the_inventory_exactly() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let tool = root.path().join("bregctl");
        fs::write(&tool, r#"#!/bin/sh
printf '%s' '{"ok":true,"explanation":{"deliveries":[{"destinationId":"declared","classificationCeiling":"public","attemptTimeoutMs":2000,"maximumAttempts":4}]}}'
"#).unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        let mut input = breg_input(false);
        input.binaries.insert(
            Product::Breg,
            crate::Binaries {
                tool: tool.clone(),
                runtime: tool,
            },
        );
        input.plan.external_breg = Some(serde_json::from_value(json!({"hooks": {
            "extra": {"origin": "http://127.0.0.1:42000", "path": "/events", "keyRef": "secret:file/key"}
        }})).unwrap());
        let terminate = AtomicBool::new(false);
        let mut runner = ProductRunner::new(Arc::new(input), root.path(), &terminate).unwrap();
        let error = runner
            .prepare_breg_hooks(root.path())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("must name exactly the BReg destinations"),
            "{error}"
        );
        assert!(runner.breg_hook_report().is_none());
    }

    #[test]
    fn messaging_metrics_use_a_separate_numeric_loopback_listener() {
        let root = tempfile::tempdir().unwrap();
        let mut input = breg_input(false);
        input.plan.products = serde_json::from_value(json!([{
            "product": "messaging", "project": ".", "audience": "messaging"
        }]))
        .unwrap();
        input.plan.people = serde_json::from_value(json!({"sender": {
            "subject": "sender", "client": "client",
            "grants": {"messaging": {"profile": "sender", "scopes": []}}
        }}))
        .unwrap();
        let terminate = AtomicBool::new(false);
        let runner = ProductRunner::new(Arc::new(input), root.path(), &terminate).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let bind = listener.local_addr().unwrap();
        let database = DatabaseUrls {
            runtime: "postgresql://runtime@localhost/fixture".to_owned(),
            migration: "postgresql://migration@localhost/fixture".to_owned(),
        };
        let config = runner
            .config(
                Product::Messaging,
                "messaging",
                &bind.to_string(),
                root.path(),
                database,
            )
            .unwrap();
        let config: Value = serde_json::from_slice(&fs::read(config).unwrap()).unwrap();
        let metrics: std::net::SocketAddr = config["metricsListener"]["bind"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(metrics.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(metrics.port(), 0);
        assert_ne!(metrics, bind);
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
    fn managed_breg_runs_write_the_same_database_identity_and_audit_path() {
        let scratch = tempfile::tempdir().unwrap();
        let mut configs = Vec::new();
        let mut keys = Vec::new();
        for run_id in ["first", "second"] {
            let root = scratch.path().join(run_id);
            private_directory(&root).unwrap();
            let mut input = breg_input(false);
            input.run_id = run_id.into();
            input.project_key = Some(crate::project_key(scratch.path(), scratch.path()));
            crate::ensure_private(&input.project_state(&root).unwrap(), true).unwrap();
            let terminate = AtomicBool::new(false);
            let runner = ProductRunner::new(Arc::new(input), &root, &terminate).unwrap();
            let (config, _) = breg_config(&runner, &root, "breg");
            configs.push(config);
            keys.push(fs::read(root.join("breg-audit-key")).unwrap());
        }
        assert_eq!(
            configs[0]["identity"]["databaseId"],
            configs[1]["identity"]["databaseId"]
        );
        assert_eq!(configs[0]["audit"]["path"], configs[1]["audit"]["path"]);
        assert!(keys[0] == keys[1], "the audit key changed on restart");
    }

    #[test]
    fn an_encrypting_run_configures_local_file_custody_with_an_owner_only_run_key() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("run");
        super::super::private_directory(&root).unwrap();
        let terminate = AtomicBool::new(false);
        let runner = ProductRunner::new(Arc::new(breg_input(true)), &root, &terminate).unwrap();

        // `bregctl field-encryption keygen` writes the key; the config only
        // names it.
        let key = root.join(FIELD_KEY);
        write_private(&key, STANDARD.encode([7u8; 32]).as_bytes()).unwrap();
        assert_eq!(field_key_file(&root), Some(key.clone()));
        let encoded = fs::read_to_string(&key).unwrap();

        // The rehearsal and the served database read the same run key, by
        // reference only. Local-file custody requires the development posture.
        for name in ["breg-test", "breg"] {
            let (config, text) = breg_config(&runner, &root, name);
            assert_eq!(
                config["fieldEncryption"],
                json!({"provider": {"type": "local-file", "dekRef": format!("secret:file/{FIELD_KEY}")}}),
                "{name}"
            );
            assert_eq!(config["secretProviders"]["file"]["root"], json!(root));
            assert_eq!(config["identity"]["environment"], "local");
            assert!(!text.contains(encoded.trim()), "{name}");
        }
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
            Product::Casework,
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
            Product::Casework,
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
                RuntimeKind::Product(Product::Breg),
                &format!("http://127.0.0.1:{unused}"),
                "/ready",
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
    fn a_migration_refusal_keeps_the_tool_source_and_exit_class() {
        use std::os::unix::process::ExitStatusExt as _;

        let root = tempfile::tempdir().unwrap();
        for (code, expected) in [
            ("migration.review.required", true),
            ("migration.change.unsupported", true),
            ("test.step.failed", false),
        ] {
            let mut output = tempfile::tempfile_in(root.path()).unwrap();
            serde_json::to_writer(
                &mut output,
                &json!({
                    "diagnostics": [{"code": code, "severity": "error"}]
                }),
            )
            .unwrap();
            let source = logged_tool_result(
                ExitStatus::from_raw(3 << 8),
                &mut output,
                root.path(),
                ("breg", "apply"),
            )
            .unwrap_err();
            let refusal = retained_breg_refusal(source, true, &["seven more".into()]);
            assert_eq!(refusal.to_string().contains("--clean"), expected);
            assert!(format!("{refusal:#}").contains(code));
            assert!(crate::is_operational(&refusal));
            assert_eq!(
                refusal
                    .downcast_ref::<LoggedToolFailure>()
                    .unwrap()
                    .status
                    .code(),
                Some(3)
            );
        }
    }

    #[test]
    fn a_kept_project_can_add_a_key_and_refuses_its_later_loss() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("run");
        super::super::private_directory(&root).unwrap();
        let mut input = breg_input(false);
        input.project_key = Some("project".into());
        let input = Arc::new(input);
        let state = input.project_state(&root).unwrap();
        super::super::private_directory(&state).unwrap();
        let terminate = AtomicBool::new(false);
        let runner = ProductRunner::new(input.clone(), &root, &terminate).unwrap();
        let name = "breg-hook-new-key";
        runner.retained_secret("breg", name, b"first").unwrap();
        assert_eq!(runner.created_kept_keys().as_slice(), &[state.join(name)]);
        drop(runner);

        let restarted = ProductRunner::new(input, &root, &terminate).unwrap();
        restarted.retained_secret("breg", name, b"second").unwrap();
        assert!(restarted.created_kept_keys().is_empty());
        let path = state.join(name);
        assert_eq!(fs::read(&path).unwrap(), b"first");
        fs::remove_file(&path).unwrap();
        let error = restarted
            .retained_secret("breg", name, b"third")
            .unwrap_err();
        assert!(error.to_string().contains(path.to_str().unwrap()));
        assert!(error.to_string().contains("--clean"));
        assert!(!path.exists());
    }

    #[test]
    fn retained_runs_refuse_missing_field_and_audit_keys_at_their_paths() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("run");
        super::super::private_directory(&root).unwrap();
        let mut input = breg_input(true);
        input.project_key = Some("project".into());
        let state = input.project_state(&root).unwrap();
        super::super::private_directory(&state).unwrap();
        let terminate = AtomicBool::new(false);
        let runner = ProductRunner::new(Arc::new(input), &root, &terminate).unwrap();
        for name in [FIELD_KEY, "breg-audit-key"] {
            let path = state.join(name);
            write_private(&path, b"test").unwrap();
            runner
                .kept_key(&state, name, |_| panic!("existing key"))
                .unwrap();
            fs::remove_file(&path).unwrap();
        }
        let field = runner.write_field_key().unwrap_err().to_string();
        let audit = runner
            .retained_secret("breg", "breg-audit-key", b"test")
            .unwrap_err()
            .to_string();
        for (name, error) in [(FIELD_KEY, field), ("breg-audit-key", audit)] {
            let path = state.join(name);
            assert!(
                error.contains(path.to_str().unwrap()) && error.contains("--clean"),
                "{error}"
            );
            assert!(!path.exists());
        }
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
