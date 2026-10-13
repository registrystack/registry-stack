// SPDX-License-Identifier: Apache-2.0

//! Borrow an issuer through public credential export and OAuth contracts.
//! No BReg state or issuer container is read or managed here.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use registry_messaging::auth::MessagingAuthenticator;
use registry_messaging::package::LoadedPackage;
use registry_messaging_core::{AccessProfile, ActorKind, Caller};
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider};
use registry_platform_oidc::{
    access_token_typ_set, parse_static_jwks, JwksFetcher, JwksFetcherConfig, TokenVerifier,
    TokenVerifierConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{config, failed, interrupted, private, refused, DevResult};

const EXPORT_LIMIT: usize = 64 * 1024;
const EXPORT_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the report of a `bregctl` that already exited may take to end.
const REPORT_DRAIN: Duration = Duration::from_secs(5);

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Binding {
    pub project: PathBuf,
    pub bregctl: PathBuf,
    pub issuer: String,
    pub token_endpoint: String,
    pub resource: String,
    pub clients: BTreeMap<String, CallerPin>,
}

/// One member of a retained binding that is not a value `messagingctl`
/// writes: what is wrong with it and what to do. Neither sentence repeats the
/// value (CFG-SEC-3).
pub(super) struct InvalidMember {
    pub member: &'static str,
    pub message: &'static str,
    pub suggested_action: &'static str,
}

impl Binding {
    /// Every member `messagingctl` would not have written, in declaration
    /// order. The token endpoint is judged against the issuer as recorded, so
    /// an invalid issuer alone does not make its own endpoint invalid.
    pub(super) fn invalid_members(&self) -> Vec<InvalidMember> {
        let loopback = self
            .issuer
            .strip_prefix("http://127.0.0.1:")
            .and_then(|port| port.parse::<u16>().ok())
            .filter(|port| *port != 0)
            .is_some_and(|port| self.issuer == format!("http://127.0.0.1:{port}"));
        let clients = if self.clients.is_empty() {
            Some("the borrowed issuer binding names no client")
        } else if self.clients.keys().any(|client| !config::file_safe(client)) {
            Some("a borrowed client name is not a bounded identifier of letters, digits, hyphens, underscores or dots")
        } else {
            None
        };
        [
            (!self.project.is_absolute()).then_some(InvalidMember {
                member: "project",
                message: "the borrowed issuer project is not an absolute path",
                suggested_action: "Preserve the file for inspection and start messagingctl dev again with --issuer-project naming the existing BReg development project.",
            }),
            (!self.bregctl.is_absolute()).then_some(InvalidMember {
                member: "bregctl",
                message: "the borrowed bregctl executable is not an absolute path",
                suggested_action: "Preserve the file for inspection, put the bregctl of this Registry Stack release on PATH, and start messagingctl dev again.",
            }),
            (!loopback).then_some(InvalidMember {
                member: "issuer",
                message: "the borrowed issuer is not one loopback origin of the form http://127.0.0.1:<port>",
                suggested_action: "Preserve the file for inspection, start the BReg development session that owns the issuer, and start messagingctl dev again to record its issuer.",
            }),
            (self.token_endpoint != format!("{}/oauth2/token", self.issuer)).then_some(
                InvalidMember {
                    member: "tokenEndpoint",
                    message: "the borrowed token endpoint is not /oauth2/token at the recorded issuer",
                    suggested_action: "Preserve the file for inspection, start the BReg development session that owns the issuer, and start messagingctl dev again to record its token endpoint.",
                },
            ),
            (!registry_platform_httputil::valid_resource_uri(&self.resource)).then_some(
                InvalidMember {
                    member: "resource",
                    message: "the borrowed resource is not an absolute resource URI without credentials or fragment",
                    suggested_action: "Preserve the file for inspection and start messagingctl dev again with --resource naming the Messaging audience registered at the issuer.",
                },
            ),
            clients.map(|message| InvalidMember {
                member: "clients",
                message,
                suggested_action: "Preserve the file for inspection and start messagingctl dev again to record the requester clients of the Messaging access profiles.",
            }),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

/// Identity consumed by Messaging, retained privately and never reported.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CallerPin {
    principal: String,
    profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_kind: Option<ActorKind>,
}

impl From<&Caller> for CallerPin {
    fn from(caller: &Caller) -> Self {
        Self {
            principal: caller.identity.subject.clone(),
            profile: caller.profile.id.clone(),
            actor_kind: caller.actor_kind,
        }
    }
}

struct Export {
    issuer: String,
    token_endpoint: String,
}

fn refusal() -> super::DevFailure {
    refused("the borrowed client could not authenticate with the Messaging profile; check the owner's client, resource, scopes and claims, then restart messagingctl dev".to_owned())
}

fn runtime() -> DevResult<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| failed("the issuer HTTP runtime could not start".to_owned()))
}

fn client_directory(root: &Path, client: &str) -> DevResult<PathBuf> {
    if !config::file_safe(client) {
        return Err(refused("the requester client cannot name a credential file; use a bounded client identifier containing letters, digits, hyphens, underscores or dots".to_owned()));
    }
    let directory = root.join("credentials").join(client);
    private::directory(&directory)
        .map_err(|_| failed("the private client credential directory is unusable".to_owned()))?;
    Ok(directory)
}

fn executable(path: &Path) -> DevResult<PathBuf> {
    let resolved = if path.components().count() > 1 {
        std::fs::canonicalize(path).ok()
    } else {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|directory| directory.join(path))
                .find(|candidate| {
                    candidate.metadata().is_ok_and(|metadata| {
                        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                    })
                })
                .and_then(|candidate| std::fs::canonicalize(candidate).ok())
        })
    };
    resolved.ok_or_else(|| {
        refused("bregctl is unavailable; put the bregctl of this Registry Stack release on PATH and restart messagingctl dev".to_owned())
    })
}

/// Bound captured output and discard stderr. Neither an upstream refusal nor
/// a misbehaving executable may put a key or bearer into our report.
///
/// The report is read on a detached thread and awaited for at most `drain`
/// after the command exits, so a process that inherited the pipe and holds it
/// open cannot keep this call waiting.
fn public_command(
    command: &mut Command,
    stop: &AtomicBool,
    timeout: Duration,
    drain: Duration,
) -> DevResult<Vec<u8>> {
    if stop.load(Ordering::SeqCst) {
        return Err(interrupted());
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| {
            refused(
                "bregctl could not run; check its executable and restart messagingctl dev"
                    .to_owned(),
            )
        })?;
    let mut stdout = child.stdout.take().expect("stdout piped");
    let (report, output) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        let mut overflow = false;
        let bytes = loop {
            match stdout.read(&mut buffer) {
                Ok(0) => break (!overflow).then_some(bytes),
                Ok(count) if !overflow && bytes.len() + count <= EXPORT_LIMIT => {
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Ok(_) => {
                    bytes.clear();
                    overflow = true;
                }
                Err(_) => break None,
            }
        };
        // The receiver is gone once the caller stopped waiting.
        let _ = report.send(bytes);
    });
    let deadline = Instant::now() + timeout;
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => {}
            Err(_) => break false,
        }
        if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if !result {
        let _ = child.kill();
        let _ = child.wait();
    }
    if stop.load(Ordering::SeqCst) {
        return Err(interrupted());
    }
    if !result {
        return Err(refused("bregctl credential export failed or timed out; check the owner project and registered client, then restart messagingctl dev".to_owned()));
    }
    output.recv_timeout(drain).ok().flatten().ok_or_else(|| {
        refused("bregctl returned an oversized or unreadable public report".to_owned())
    })
}

fn export(
    bregctl: &Path,
    project: &Path,
    client: &str,
    directory: &Path,
    stop: &AtomicBool,
) -> DevResult<Export> {
    let id = directory.join("client-id");
    let key = directory.join("assertion-key.jwk");
    let bytes = public_command(
        Command::new(bregctl)
            .args(["--format", "json", "dev", "export-client"])
            .arg(project)
            .args(["--client", client, "--client-id-file"])
            .arg(&id)
            .arg("--assertion-key-file")
            .arg(&key),
        stop,
        EXPORT_TIMEOUT,
        REPORT_DRAIN,
    )?;
    let report: Value = serde_json::from_slice(&bytes)
        .map_err(|_| refused("bregctl returned no usable public credential report".to_owned()))?;
    if report["ok"] != true
        || report["client"] != client
        || report["clientIdFile"] != id.to_string_lossy().as_ref()
        || report["assertionKeyFile"] != key.to_string_lossy().as_ref()
    {
        return Err(refused("bregctl reported a different client or credential output; restart with the intended bregctl executable".to_owned()));
    }
    let issuer = report["issuer"].as_str().ok_or_else(refusal)?;
    let port = issuer
        .strip_prefix("http://127.0.0.1:")
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0 && issuer == format!("http://127.0.0.1:{port}"))
        .ok_or_else(|| {
            refused("the borrowed issuer must be one exact numeric-loopback HTTP origin".to_owned())
        })?;
    let issuer = format!("http://127.0.0.1:{port}");
    let token_endpoint = format!("{issuer}/oauth2/token");
    if report["tokenEndpoint"] != token_endpoint || report["clientAssertionAudience"] != issuer {
        return Err(refused(
            "the exported token endpoint and assertion audience do not match the local issuer"
                .to_owned(),
        ));
    }
    let exported_id = Zeroizing::new(private::read(&id, 4096).map_err(|_| refusal())?);
    if exported_id.as_slice() != client.as_bytes() {
        return Err(refusal());
    }
    // The real OAuth grant below proves the explicit Messaging resource,
    // rather than relying on the public report's advertised resource.
    Ok(Export {
        issuer,
        token_endpoint,
    })
}

fn profile<'a>(loaded: &'a LoadedPackage, client: &str) -> DevResult<&'a AccessProfile> {
    loaded
        .package
        .access_profiles()
        .iter()
        .find(|profile| profile.requester_clients.iter().any(|id| id == client))
        .ok_or_else(|| refused("no Messaging access profile names this client".to_owned()))
}

async fn acquire(
    root: &Path,
    loaded: &LoadedPackage,
    binding: &Binding,
    client: &str,
) -> DevResult<(Zeroizing<String>, u64, CallerPin)> {
    let profile = profile(loaded, client)?;
    let bytes = Zeroizing::new(
        private::read(
            &root
                .join("credentials")
                .join(client)
                .join("assertion-key.jwk"),
            4096,
        )
        .map_err(|_| refusal())?,
    );
    let text = Zeroizing::new(String::from_utf8(bytes.to_vec()).map_err(|_| refusal())?);
    let key = PrivateJwk::parse(&text).map_err(|_| refusal())?;
    let mut settings = PrivateKeyJwtConfig::new(
        binding.token_endpoint.parse().map_err(|_| refusal())?,
        client,
        key,
    )
    .with_audience(&binding.issuer)
    .with_resource(&binding.resource);
    if !profile.required_scopes.is_empty() {
        settings = settings.with_scopes(profile.required_scopes.clone());
    }
    let bearer = PrivateKeyJwt::new(settings)
        .map_err(|_| refusal())?
        .bearer_token()
        .await
        .map_err(|_| refusal())?;
    let header = bearer.authorization_header_value();
    let signed = Zeroizing::new(
        header
            .to_str()
            .map_err(|_| refusal())?
            .strip_prefix("Bearer ")
            .ok_or_else(refusal)?
            .to_owned(),
    );
    verify(root, loaded, binding, client, &signed)
        .await
        .map(|(expires, caller)| (signed, expires, caller))
}

pub(super) async fn verify(
    root: &Path,
    loaded: &LoadedPackage,
    binding: &Binding,
    client: &str,
    signed: &str,
) -> DevResult<(u64, CallerPin)> {
    let bytes =
        private::read(&root.join("secrets/jwks.json"), 256 * 1024).map_err(|_| refusal())?;
    let keys = Arc::new(JwksFetcher::new_static(
        parse_static_jwks(&bytes).map_err(|_| refusal())?,
        JwksFetcherConfig::defaults(),
    ));
    let verifier = TokenVerifierConfig::access_token_profile(
        binding.issuer.clone(),
        vec![binding.resource.clone()],
        vec![
            jsonwebtoken::Algorithm::RS256,
            jsonwebtoken::Algorithm::ES256,
        ],
        access_token_typ_set("at+jwt"),
    )
    .with_scope_claim("scope")
    .with_allowed_clients(
        loaded
            .package
            .access_profiles()
            .iter()
            .flat_map(|profile| profile.requester_clients.iter().cloned())
            .collect(),
    );
    let verified = TokenVerifier::new(verifier.clone(), keys.clone())
        .verify(signed)
        .await
        .map_err(|_| refusal())?;
    if verified.matched_client_id().map_err(|_| refusal())? != Some(client) {
        return Err(refusal());
    }
    let caller = MessagingAuthenticator::new(
        verifier,
        keys,
        loaded.package.access_profiles().clone(),
        false,
    )
    .authenticate(signed)
    .await
    .map_err(|_| refusal())?;
    if caller.profile.id != profile(loaded, client)?.id {
        return Err(refusal());
    }
    let expires = verified
        .claims
        .exp
        .ok_or_else(refusal)?
        .saturating_sub(chrono::Utc::now().timestamp())
        .max(0) as u64;
    Ok((expires, CallerPin::from(&caller)))
}

pub(super) fn capture(
    root: &Path,
    loaded: &LoadedPackage,
    project: &Path,
    resource: &str,
    bregctl: &Path,
    stop: &AtomicBool,
) -> DevResult<Binding> {
    let project = std::fs::canonicalize(project).map_err(|_| {
        refused(
            "the issuer project cannot be read; select the existing BReg development project"
                .to_owned(),
        )
    })?;
    let bregctl = executable(bregctl)?;
    private::directory(&root.join("credentials")).map_err(|_| refusal())?;
    let mut binding = Binding {
        project,
        bregctl,
        issuer: String::new(),
        token_endpoint: String::new(),
        resource: resource.to_owned(),
        clients: BTreeMap::new(),
    };
    for profile in loaded.package.access_profiles().iter() {
        for client in &profile.requester_clients {
            let directory = client_directory(root, client)?;
            let exported = export(&binding.bregctl, &binding.project, client, &directory, stop)?;
            if !binding.issuer.is_empty()
                && (binding.issuer != exported.issuer
                    || binding.token_endpoint != exported.token_endpoint)
            {
                return Err(refused(
                    "the clients do not share one exact issuer; correct the owner registrations"
                        .to_owned(),
                ));
            }
            binding.issuer = exported.issuer;
            binding.token_endpoint = exported.token_endpoint;
        }
    }
    let port = binding
        .issuer
        .strip_prefix("http://127.0.0.1:")
        .and_then(|port| port.parse::<u16>().ok())
        .ok_or_else(refusal)?;
    let runtime = runtime()?;
    let jwks = runtime.block_on(registry_thunderid_tooling::local::snapshot(port))
        .map_err(|_| refused("the borrowed issuer is unavailable or its public keys are invalid; start the issuer owner and retry".to_owned()))?;
    private::create(&root.join("secrets/jwks.json"), jwks.to_string().as_bytes())
        .map_err(|_| refusal())?;
    for profile in loaded.package.access_profiles().iter() {
        for client in &profile.requester_clients {
            if stop.load(Ordering::SeqCst) {
                return Err(interrupted());
            }
            let (_, _, caller) = runtime.block_on(acquire(root, loaded, &binding, client))?;
            binding.clients.insert(client.clone(), caller);
        }
    }
    Ok(binding)
}

pub(super) fn same_export(root: &Path, scratch: &Path, client: &str) -> DevResult<()> {
    for file in ["client-id", "assertion-key.jwk"] {
        let retained = Zeroizing::new(
            private::read(&root.join("credentials").join(client).join(file), 4096)
                .map_err(|_| refusal())?,
        );
        let exported =
            Zeroizing::new(private::read(&scratch.join(file), 4096).map_err(|_| refusal())?);
        if retained.as_slice() != exported.as_slice() {
            return Err(refused("the borrowed client credentials changed; restart messagingctl dev to capture the current issuer".to_owned()));
        }
    }
    Ok(())
}

pub(super) fn same_caller(expected: &CallerPin, actual: &CallerPin) -> DevResult<()> {
    if expected != actual {
        return Err(refused("the borrowed client's identity changed; restart messagingctl dev to capture the current issuer".to_owned()));
    }
    Ok(())
}

pub(super) fn refresh(
    root: &Path,
    loaded: &LoadedPackage,
    binding: &Binding,
    client: &str,
) -> DevResult<(Zeroizing<String>, u64)> {
    profile(loaded, client)?;
    let expected = binding.clients.get(client).ok_or_else(refusal)?;
    let scratch = tempfile::Builder::new()
        .prefix(".client-check-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(root)
        .map_err(|_| refusal())?;
    private::check(scratch.path(), true).map_err(|_| refusal())?;
    let exported = export(
        &binding.bregctl,
        &binding.project,
        client,
        scratch.path(),
        &AtomicBool::new(false),
    )?;
    if exported.issuer != binding.issuer || exported.token_endpoint != binding.token_endpoint {
        return Err(refused(
            "the borrowed issuer endpoints changed; restart messagingctl dev".to_owned(),
        ));
    }
    same_export(root, scratch.path(), client)?;
    let (signed, expires, caller) = runtime()?.block_on(acquire(root, loaded, binding, client))?;
    same_caller(expected, &caller)?;
    Ok((signed, expires))
}

#[cfg(test)]
#[path = "borrowed_tests.rs"]
mod tests;
