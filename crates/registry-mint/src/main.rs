//! The `mint` binary.
//!
//! `check` validates a deployment without opening a socket and `serve` runs the
//! token endpoint; `SIGHUP` reloads the client registry in place so onboarding
//! a caller never restarts the service. `client-secret` provisions compatible
//! managed clients without printing their raw credential.
//!
//! `token` is the odd one out: it is a *caller* tool, not an operator one. It
//! reads no server configuration and never touches Mint's signing key. It signs
//! a client assertion with the caller's own key and presents it to a running
//! token endpoint, which then decides on its own terms. Obtaining a token still
//! requires authenticating, in the CLI exactly as over the wire.

use std::{collections::BTreeMap, path::Path, process::ExitCode, sync::Arc};

use clap::Parser;
use registry_mint::cli::{Cli, ClientSecretCommand, Command};
use registry_mint::{
    audit::MintAuditLog,
    caller::{sign_client_assertion, AssertionRequest},
    client_secret,
    config::MintConfig,
    secretfile,
    server::{healthcheck, serve, MintService},
    CLIENT_ASSERTION_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS,
};
use registry_platform_audit::OptionalHashHex;
use serde_json::Value;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // `token` writes the access token to stdout and nothing else, so its
    // diagnostics go to stderr and the caller can pipe the token straight into
    // whatever needs it. The services keep structured logs on stdout.
    let logs = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json();
    if matches!(
        cli.command,
        Command::Token { .. } | Command::ClientSecret { .. } | Command::Healthcheck { .. }
    ) {
        logs.with_writer(std::io::stderr).init();
    } else {
        logs.init();
    }

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Startup failures name the failing stage, never the key material
            // or the file contents that produced them.
            tracing::error!(target: "registry_mint", "{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Check {
            config,
            require_runtime_dependencies,
            require_audit_under: audit_root,
        } => {
            let config = MintConfig::load(&config)
                .map_err(|error| format!("the configuration could not be loaded: {error}"))?;
            // The deployment owns storage persistence and declares the root it
            // mounts; Mint owns where the sink resolves. Proving containment
            // before the writer is claimed keeps the two boundaries separate
            // and never relaxes the readiness proof below.
            if let Some(root) = audit_root.as_deref() {
                registry_platform_audit::require_audit_under(&config.audit.path, root)
                    .map_err(|fault| format!("the audit destination check failed: {fault}"))?;
            }
            let issuer = config.issuer.clone();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("the async runtime could not start: {error}"))?;
            let clients = if require_runtime_dependencies {
                let service = runtime
                    .block_on(MintService::load(config))
                    .map_err(|error| format!("the runtime dependencies are not ready: {error}"))?;
                if !runtime.block_on(service.ready()) {
                    return Err("the runtime dependencies are not ready".to_owned());
                }
                service.client_count()
            } else {
                runtime
                    .block_on(MintService::check(&config))
                    .map_err(|error| format!("the configuration cannot be served: {error}"))?
            };
            tracing::info!(
                target: "registry_mint",
                issuer,
                clients,
                "configuration is valid"
            );
            Ok(())
        }
        Command::Healthcheck { url } => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| "the readiness probe failed".to_owned())?;
            runtime
                .block_on(healthcheck(&url))
                .map_err(|_| "the readiness probe failed".to_owned())
        }
        Command::Serve { config } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("the async runtime could not start: {error}"))?;
            runtime.block_on(async move {
                let service = Arc::new(load(&config).await?);
                let reloads = Arc::clone(&service);
                tokio::spawn(async move { reload_on_hangup(reloads).await });
                serve(service, shutdown_signal())
                    .await
                    .map_err(|error| format!("the listener failed: {error}"))
            })
        }
        Command::VerifyAudit { config } => {
            let config = MintConfig::load(&config)
                .map_err(|error| format!("the configuration could not be loaded: {error}"))?;
            let summary = MintAuditLog::verify(&config.audit, &config.secret_providers)
                .map_err(|error| format!("the audit chain did not verify: {error}"))?;
            let sealed_sequence = match (summary.first_sequence, summary.last_sequence) {
                (Some(first), Some(last)) => format!("{first}-{last}"),
                _ => "none".to_owned(),
            };
            let active_segment = if summary.active_verified {
                "verified"
            } else {
                "not verified: a running writer holds it, so only sealed history was proven"
            };
            println!(
                "segments: {}\nrecords: {}\nsealed-sequence: {}\nhead: {}\nactive-segment: {}",
                summary.segments,
                summary.records,
                sealed_sequence,
                OptionalHashHex(summary.last_hash),
                active_segment,
            );
            Ok(())
        }
        Command::ClientSecret { command } => match command {
            ClientSecretCommand::Generate { out } => {
                let fingerprint = client_secret::generate(&out).map_err(|error| {
                    format!("the client secret could not be generated: {error}")
                })?;
                println!("{fingerprint}");
                Ok(())
            }
        },
        Command::Token {
            url,
            client_id,
            key,
            audience,
            actor,
            subject_file,
            lifetime_seconds,
            ca_certificate,
            verbose,
        } => {
            // The caller's key gets the same file guarantees as Mint's own:
            // a regular file, owned by this user, unreadable by anyone else,
            // and reached without traversing a symlink.
            let key = secretfile::read_owner_only(&key)
                .map_err(|error| format!("the client key could not be read: {error}"))?;
            let key = registry_platform_crypto::PrivateJwk::parse(&key)
                .map_err(|error| format!("the client key is not a usable private JWK: {error}"))?;

            let subject = subject_file.as_deref().map(read_subject).transpose()?;
            let assertion = sign_client_assertion(
                &key,
                &AssertionRequest {
                    client_id: &client_id,
                    audience: audience.as_deref().unwrap_or(&url),
                    lifetime_seconds,
                    actor: actor.as_deref(),
                    subject,
                },
                now_seconds()?,
            )
            .map_err(|error| format!("the client assertion could not be built: {error}"))?;

            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("the async runtime could not start: {error}"))?;
            let response =
                runtime.block_on(request_token(&url, &assertion, ca_certificate.as_deref()))?;

            if verbose {
                println!("{response}");
            } else {
                let token = response
                    .get("access_token")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "the endpoint returned no access token".to_owned())?;
                println!("{token}");
            }
            Ok(())
        }
    }
}

/// Read the delegation subject: a flat JSON object of selector fields.
fn read_subject(path: &Path) -> Result<BTreeMap<String, Value>, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("the subject file could not be read: {error}"))?;
    let subject: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("the subject file is not JSON: {error}"))?;
    let Value::Object(fields) = subject else {
        return Err("the subject file must hold a JSON object of selector fields".to_owned());
    };
    // Selector values are scalars. Rejecting anything else here names the
    // problem, where the endpoint could only answer `invalid_client`.
    for (name, value) in &fields {
        if value.is_object() || value.is_array() || value.is_null() {
            return Err(format!("the subject field `{name}` must be a scalar value"));
        }
    }
    Ok(fields.into_iter().collect())
}

async fn request_token(
    url: &str,
    assertion: &str,
    ca_certificate: Option<&Path>,
) -> Result<Value, String> {
    let mut client = reqwest::Client::builder();
    if let Some(path) = ca_certificate {
        let pem = std::fs::read(path)
            .map_err(|error| format!("the CA certificate could not be read: {error}"))?;
        for certificate in reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|error| format!("the CA certificate could not be parsed: {error}"))?
        {
            client = client.add_root_certificate(certificate);
        }
    }
    let client = client
        .build()
        .map_err(|error| format!("the HTTP client could not be built: {error}"))?;

    let response = client
        .post(url)
        .form(&[
            ("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE),
            ("client_assertion", assertion),
        ])
        .send()
        .await
        .map_err(|error| format!("the token request failed: {error}"))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| format!("the token response could not be read: {error}"))?;
    if !status.is_success() {
        // The request carried a signed client assertion, which is a bearer
        // credential at the endpoint it is bound to until it expires. Whatever
        // answered here is not necessarily that endpoint, and a refusal body is
        // free to quote the form back. Report the two bounded OAuth fields and
        // drop the rest rather than write the assertion into stderr, the
        // operator's logs, and their scrollback.
        return Err(format!(
            "the endpoint refused the request ({status}): {}",
            oauth_error(&body)
        ));
    }
    serde_json::from_str(&body).map_err(|error| format!("the token response is not JSON: {error}"))
}

/// Summarize a refusal using only the two fields RFC 6749 defines for one.
///
/// Both are reproduced as printable ASCII within the length the RFC's own
/// grammar allows, so a hostile or merely careless endpoint cannot use the
/// refusal to write arbitrary bytes, control sequences, or the caller's own
/// request into the terminal.
fn oauth_error(body: &str) -> String {
    let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(body) else {
        return "the response carried no OAuth error".to_owned();
    };
    let field = |name: &str| -> Option<String> {
        let value = fields.get(name)?.as_str()?;
        let bounded: String = value
            .chars()
            .filter(|character| {
                character.is_ascii_graphic() || *character == ' ' || *character == '\t'
            })
            .take(200)
            .collect();
        (!bounded.is_empty()).then_some(bounded)
    };
    match (field("error"), field("error_description")) {
        (Some(error), Some(description)) => format!("{error}: {description}"),
        (Some(error), None) => error,
        _ => "the response carried no OAuth error".to_owned(),
    }
}

fn now_seconds() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .map_err(|_| "the system clock is before the Unix epoch".to_owned())
}

async fn load(config: &Path) -> Result<MintService, String> {
    let config = MintConfig::load(config)
        .map_err(|error| format!("the configuration could not be loaded: {error}"))?;
    MintService::load(config)
        .await
        .map_err(|error| format!("the service could not start: {error}"))
}

/// Reload the client registry on every `SIGHUP`, keeping the previous registry
/// when the new one does not load.
async fn reload_on_hangup(service: Arc<MintService>) {
    let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(hangup) => hangup,
        Err(error) => {
            tracing::error!(target: "registry_mint", "the hangup handler could not be installed: {error}");
            return;
        }
    };
    while hangup.recv().await.is_some() {
        match service.reload_clients() {
            Ok(clients) => {
                tracing::info!(target: "registry_mint", clients, "client registry reloaded");
            }
            Err(error) => {
                tracing::error!(
                    target: "registry_mint",
                    "the client registry was not reloaded and the previous one is still in use: {error}"
                );
            }
        }
    }
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}
