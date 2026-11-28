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
    pub(super) fn origin(&self) -> &str {
        &self.origin
    }

    pub(super) fn start(listener: TcpListener, jwks: &Value) -> Result<Self> {
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
    /// into the adopter's tree. A project's own `local-target.yaml` and the
    /// authority it names are copied into the run's target, with development
    /// secrets generated for every secret it references. A project without one
    /// gets `evidencectl target new --local`, which derives a target and
    /// authority from the definitions' ceilings. The target is pointed at the
    /// run's listener, issuer and key set, and the package and authority are
    /// built and activated the way a deployment would.
    pub(super) fn activate_evidence(&mut self, project: &Path, bind: &str) -> Result<PathBuf> {
        let plan = &self.input.plan;
        let work = self.root.join("evidence-project");
        copy_project(project, &work)?;
        let target_dir = self.root.join("evidence-target");
        let candidate = self.root.join(CANDIDATE_DIRECTORY);
        let package_root = self.root.join(PACKAGE_DIRECTORY);
        // `target new` prints no JSON report, so it runs without `--format json`.
        self.ensure_active()?;
        let secrets = work.join(".generated").join("secrets");
        let authored_target = work.join(AUTHORED_TARGET_FILE);
        let mut new_target: Vec<&std::ffi::OsStr> =
            vec!["target".as_ref(), "new".as_ref(), target_dir.as_os_str()];
        if authored_target.try_exists()? {
            self.generate_authored_secrets(&authored_target, &work, &secrets)?;
            new_target.extend(["--settings".as_ref(), authored_target.as_os_str()]);
        } else {
            new_target.extend(["--local".as_ref(), "--project".as_ref(), work.as_os_str()]);
        }
        run_logged_tool(
            &self.input.binaries[&Product::Evidence].tool,
            &new_target,
            self.root,
            ("evidence", "target"),
            false,
            || self.ensure_active(),
        )?;
        let jwks = if plan.jwks_uri().is_some() {
            None
        } else {
            let listener = self
                .issuer_listener
                .take()
                .context("the run issuer listener is not reserved")?;
            Some(JwksServer::start(listener, &self.issuer_jwks()?)?)
        };
        let jwks_uri = jwks
            .as_ref()
            .map(JwksServer::uri)
            .or_else(|| plan.jwks_uri().map(str::to_owned))
            .context("missing Evidence key endpoint")?;
        let target_file = target_dir.join("target.yaml");
        let missing = self.point_target_at_run(
            &target_file,
            (bind, &jwks_uri),
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
        self.jwks = jwks;
        Ok(config)
    }

    /// Makes the development secrets an authored target references, in the
    /// secret root the run points the target at: the signing keypair at the
    /// target's own `publicJwkFile`, the subject-binding and audit hash keys.
    /// Source tokens are made after the target is pointed at the run. A secret
    /// that already exists is kept.
    fn generate_authored_secrets(
        &self,
        authored_target: &Path,
        work: &Path,
        secrets: &Path,
    ) -> Result<()> {
        let target = read_yaml(authored_target)?;
        let secret_name = |reference: &Value| {
            reference
                .as_str()
                .and_then(|text| text.strip_prefix("secret:file/"))
                .map(str::to_owned)
        };
        if target["signer"]["type"] == "local-jwk" {
            let private = secret_name(&target["signer"]["privateKeyRef"]).context(
                "the authored target's signer privateKeyRef must be a secret:file/ reference",
            )?;
            let public = Path::new(
                target["signer"]["publicJwkFile"]
                    .as_str()
                    .context("the authored target's signer needs a publicJwkFile")?,
            );
            ensure!(
                public.is_relative()
                    && public
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "the authored target's publicJwkFile must be a path inside the project"
            );
            ensure!(
                private == GENERATED_SIGNING_KEY,
                "the run generates its signing key as secret:file/{GENERATED_SIGNING_KEY}; \
                 name that key as the authored target's signer privateKeyRef"
            );
            if !secrets.join(&private).exists() {
                self.tool(
                    Product::Evidence,
                    "keygen",
                    &[
                        "signing".as_ref(),
                        "--output-dir".as_ref(),
                        secrets.as_os_str(),
                        "--public-output".as_ref(),
                        work.join(public).as_os_str(),
                    ],
                )?;
            }
        }
        for reference in [
            &target["subjectBinding"]["secretRef"],
            &target["audit"]["hashKeyRef"],
        ] {
            let Some(name) = secret_name(reference) else {
                continue;
            };
            if !secrets.join(&name).exists() {
                self.tool(
                    Product::Evidence,
                    "keygen",
                    &[
                        "secret".as_ref(),
                        "--output".as_ref(),
                        secrets.join(name).as_os_str(),
                    ],
                )?;
            }
        }
        Ok(())
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
        let mut target = read_yaml(target_file)?;
        let oidc = &mut target["authentication"]["oidc"];
        // The run issuer is the key set server's own origin: a local Evidence
        // target accepts only a canonical loopback issuer whose key set is
        // served from that origin.
        if self.input.plan.jwks_uri().is_some() {
            oidc["issuer"] = json!(self.input.plan.issuer);
            oidc["jwksSource"] = json!({"type": "uri", "uri": jwks_uri});
            oidc["audience"] = json!(audience);
        } else {
            configure_run_oidc(oidc, &self.input.plan.issuer, jwks_uri, audience);
        }
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

/// Points a target's token settings at what the run issuer emits. The issuer
/// signs ES256 access tokens and names the claims the same way for every
/// project, so an authored target's own algorithm and claim names, including
/// renamed actor-kind and grant claims, give way to its defaults.
fn configure_run_oidc(oidc: &mut Value, issuer: &str, jwks_uri: &str, audience: &str) {
    oidc["issuer"] = json!(issuer);
    oidc["jwksSource"] = json!({"type": "uri", "uri": jwks_uri});
    oidc["audience"] = json!(audience);
    oidc["maximumTokenLifetimeSeconds"] = json!(crate::issuer::TOKEN_LIFETIME_SECONDS);
    oidc["tokenTypes"] = json!(["at+jwt"]);
    oidc["algorithms"] = json!(["ES256"]);
    oidc["principalClaim"] = json!("sub");
    oidc["requesterTagsClaim"] = json!("evidence_tags");
    oidc["evidenceAudienceClaim"] = json!("evidence_audience");
    if let Some(settings) = oidc.as_object_mut() {
        settings.remove("claims");
    }
}

/// The target a project authors beside its Sources.
const AUTHORED_TARGET_FILE: &str = "local-target.yaml";

/// The signing key's file name in the secret root, which `evidencectl keygen
/// signing` fixes.
const GENERATED_SIGNING_KEY: &str = "signing-p256-private-jwk";

/// Reads a YAML file as JSON.
fn read_yaml(path: &Path) -> Result<Value> {
    let text =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(
        registry_platform_yaml::Reader::new(path.display().to_string())
            .scan(text.as_bytes())
            .map_err(|_| anyhow::anyhow!("{} is not valid YAML", path.display()))?
            .with_context(|| format!("{} is empty", path.display()))?
            .to_json_value(),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_authored_target_reads_the_run_issuer_claims() {
        let mut oidc = json!({
            "issuer": "https://unused.example.test",
            "jwksSource": {"type": "uri", "uri": "https://unused.example.test/keys"},
            "tokenTypes": ["JWT"],
            "algorithms": ["RS256"],
            "principalClaim": "client_id",
            "requesterTagsClaim": "roles",
            "evidenceAudienceClaim": "aud_evidence",
            "claims": {"actorKind": "kind", "purpose": "why"},
        });
        let issuer = "http://127.0.0.1:36001";
        let key_set = format!("{issuer}/jwks");
        configure_run_oidc(&mut oidc, issuer, &key_set, "urn:example:evidence");
        assert_eq!(
            oidc,
            json!({
                "issuer": issuer,
                "jwksSource": {"type": "uri", "uri": key_set},
                "audience": "urn:example:evidence",
                "maximumTokenLifetimeSeconds": 3600,
                "tokenTypes": ["at+jwt"],
                "algorithms": ["ES256"],
                "principalClaim": "sub",
                "requesterTagsClaim": "evidence_tags",
                "evidenceAudienceClaim": "evidence_audience",
            })
        );
    }
}
