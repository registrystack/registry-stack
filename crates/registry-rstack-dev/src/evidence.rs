// SPDX-License-Identifier: Apache-2.0
//! Evidence under `rstack dev`: a local target for the project, its package and
//! authority, and the loopback key set that stands in for the identity provider.
//! Evidence keeps no database and starts no source, so a run of Evidence alone
//! needs neither PostgreSQL nor Docker. This module is part of `products`, which
//! owns the run's directory, tool spawning and logs.

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

use super::*;

/// How long the key set server waits on one client before it drops it.
const JWKS_CLIENT_TIMEOUT: Duration = Duration::from_secs(2);
/// The largest request head the key set server reads.
const JWKS_REQUEST_LIMIT: usize = 8 * 1024;

/// A loopback HTTP server on the run issuer's reserved listener that answers
/// every GET with the issuer's public key set. The generated Evidence target
/// fetches the keys by URI, and nothing else serves them when Evidence runs
/// alone, so the runner serves them for as long as Evidence runs.
pub(super) struct JwksServer {
    origin: String,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl JwksServer {
    fn start(listener: TcpListener, jwks: &Value) -> Result<Self> {
        listener.set_nonblocking(true)?;
        let origin = format!("http://{}", listener.local_addr()?);
        let body = serde_json::to_vec(jwks)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = thread::Builder::new()
            .name("rstack-dev-jwks".into())
            .spawn({
                let stop = stop.clone();
                move || {
                    while !stop.load(Ordering::Relaxed) {
                        match listener.accept() {
                            Ok((stream, _)) => serve_jwks(stream, &body),
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(10));
                            }
                            Err(_) => break,
                        }
                    }
                }
            })?;
        Ok(Self {
            origin,
            stop,
            thread: Some(thread),
        })
    }

    fn uri(&self) -> String {
        format!("{}/jwks", self.origin)
    }
}

impl Drop for JwksServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            // The accept loop polls the flag and ends within a poll interval.
            let _ = thread.join();
        }
    }
}

/// Answers one request: the key set for a GET, nothing else. A client that
/// stalls or sends more than a request head is dropped.
fn serve_jwks(mut stream: TcpStream, body: &[u8]) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(JWKS_CLIENT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(JWKS_CLIENT_TIMEOUT));
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => head.extend_from_slice(&chunk[..read]),
        }
        if head.len() > JWKS_REQUEST_LIMIT {
            return;
        }
    }
    let response = if head.starts_with(b"GET ") {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    } else {
        b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            .to_vec()
    };
    // A client that left early is the client's loss.
    let _ = stream.write_all(&response);
}

impl ProductRunner<'_> {
    /// Prepares the project for a run and returns the runtime configuration
    /// `evidence serve` reads. The project is copied so the run never writes
    /// into the adopter's tree. `evidencectl target new --local` makes the
    /// target and its development secrets, the target is pointed at the run's
    /// listener, issuer and key set, and the package and authority are built
    /// and activated the way a deployment would.
    pub(super) fn activate_evidence(&mut self, project: &Path, bind: &str) -> Result<PathBuf> {
        let plan = &self.input.plan;
        let work = self.root.join("evidence-project");
        copy_project(project, &work)?;
        let target_dir = self.root.join("evidence-target");
        let candidate = self.root.join(CANDIDATE_DIRECTORY);
        let package_root = self.root.join(PACKAGE_DIRECTORY);
        // `target new` prints no JSON report, so it runs without `--format json`.
        self.ensure_active()?;
        run_logged_tool(
            &self.input.binaries[&Product::Evidence].tool,
            &[
                "target".as_ref(),
                "new".as_ref(),
                target_dir.as_os_str(),
                "--local".as_ref(),
                "--project".as_ref(),
                work.as_os_str(),
            ],
            self.root,
            ("evidence", "target"),
            false,
            || self.ensure_active(),
        )?;
        let listener = self
            .issuer_listener
            .take()
            .context("the run issuer listener is not reserved")?;
        let jwks = JwksServer::start(listener, &self.issuer_jwks()?)?;
        let secrets = work.join(".generated").join("secrets");
        let target_file = target_dir.join("target.yaml");
        let missing = self.point_target_at_run(
            &target_file,
            (bind, &jwks.uri()),
            &secrets,
            &package_root,
            &plan.product(Product::Evidence).audience,
        )?;
        for name in missing {
            self.tool(
                Product::Evidence,
                "keygen",
                &[
                    "token".as_ref(),
                    "--output".as_ref(),
                    secrets.join(name).as_os_str(),
                ],
            )?;
        }
        let target_argument = ["--target".as_ref(), target_file.as_os_str()];
        self.tool(
            Product::Evidence,
            "check",
            &[&[work.as_os_str()], &target_argument[..]].concat(),
        )?;
        self.tool(
            Product::Evidence,
            "package",
            &[
                &[work.as_os_str()][..],
                &target_argument[..],
                &["--output".as_ref(), candidate.as_os_str()][..],
            ]
            .concat(),
        )?;
        // The runtime reads the package from the target's package root, which
        // is not the packaging output.
        copy_project(&candidate.join("bundle"), &package_root)?;
        set_tree_mode(&package_root, 0o555, 0o444)?;
        let config = candidate.join("runtime.yaml");
        let document = candidate.join("compiled-authority.yaml");
        run_logged_tool(
            &self.input.binaries[&Product::Evidence].runtime,
            &[
                "authority".as_ref(),
                "activate".as_ref(),
                "--runtime-config".as_ref(),
                config.as_os_str(),
                "--document".as_ref(),
                document.as_os_str(),
            ],
            self.root,
            ("evidence", "activate"),
            false,
            || self.ensure_active(),
        )?;
        self.jwks = Some(jwks);
        Ok(config)
    }

    fn issuer_jwks(&self) -> Result<Value> {
        self.issuer
            .as_ref()
            .map(|issuer| issuer.public_jwks())
            .context("the run issuer is not ready")
    }

    /// Rewrites the generated target for this run and returns the names of the
    /// development secrets its connections reference that do not exist yet.
    fn point_target_at_run(
        &self,
        target_file: &Path,
        (bind, jwks_uri): (&str, &str),
        secrets: &Path,
        package: &Path,
        audience: &str,
    ) -> Result<Vec<String>> {
        let text = fs::read_to_string(target_file).context("cannot read the Evidence target")?;
        let mut target = registry_platform_yaml::Reader::new(target_file.display().to_string())
            .scan(text.as_bytes())
            .map_err(|_| anyhow::anyhow!("the Evidence target is not valid YAML"))?
            .context("the Evidence target is empty")?
            .to_json_value();
        let oidc = &mut target["authentication"]["oidc"];
        // The run issuer is the key set server's own origin: a local Evidence
        // target accepts only a canonical loopback issuer whose key set is
        // served from that origin.
        oidc["issuer"] = json!(self.input.plan.issuer);
        oidc["jwksSource"] = json!({"type": "uri", "uri": jwks_uri});
        oidc["audience"] = json!(audience);
        target["listener"]["bind"] = json!(bind);
        target["service"]["publicOrigin"] = json!(format!("http://{bind}"));
        target["package"]["root"] = json!(package);
        target["secretProviders"]["file"]["root"] = json!(secrets);
        target["audit"]["path"] = json!(self.root.join("evidence-audit.jsonl"));
        let mut references = Vec::new();
        collect_file_secrets(&target["connections"], &mut references);
        write_private(target_file, serde_norway::to_string(&target)?.as_bytes())?;
        Ok(references
            .into_iter()
            .filter(|name| !secrets.join(name).exists())
            .collect())
    }
}

/// The run's Evidence package directory name, inside the run directory.
const PACKAGE_DIRECTORY: &str = "evidence-package";

/// The run's Evidence packaging output directory name, inside the run directory.
const CANDIDATE_DIRECTORY: &str = "evidence-candidate";

/// Makes the run's Evidence package and packaging output writable again so the
/// run directory can be removed. Evidence refuses a package that is not
/// read-only, and `evidencectl package` writes its output read-only.
pub(super) fn unlock_package(root: &Path) -> Result<()> {
    for name in [PACKAGE_DIRECTORY, CANDIDATE_DIRECTORY] {
        let directory = root.join(name);
        if directory.exists() {
            set_tree_mode(&directory, 0o755, 0o644)?;
        }
    }
    Ok(())
}

/// Sets every directory under `path`, itself included, to `directory_mode` and
/// every file to `file_mode`. A directory is opened up before its entries are
/// read and closed after, so both directions can walk the tree.
fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "the Evidence package contains a symlink"
    );
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        for entry in fs::read_dir(path)? {
            set_tree_mode(&entry?.path(), directory_mode, file_mode)?;
        }
        fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))?;
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode))?;
    }
    Ok(())
}

/// The names of every `secret:file/<name>` reference under `value`.
fn collect_file_secrets(value: &Value, names: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            if let Some(name) = text.strip_prefix("secret:file/") {
                names.push(name.to_owned());
            }
        }
        Value::Array(items) => items
            .iter()
            .for_each(|item| collect_file_secrets(item, names)),
        Value::Object(map) => map
            .values()
            .for_each(|item| collect_file_secrets(item, names)),
        _ => {}
    }
}
