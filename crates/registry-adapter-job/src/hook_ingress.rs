// SPDX-License-Identifier: Apache-2.0

//! Separate authenticated ingress for job hook triggers.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures::StreamExt as _;
use registry_adapter_core::AdapterJob;
use registry_adapter_engine::job_sources::{HookSourceConfig, JobRuntimeConfig};
use registry_platform_config::{ProtectedSecret, SecretError, SecretResolver};
use registry_platform_crypto::mac::constant_time_eq;
use registry_platform_ratelimit::token_bucket::{
    TokenBucketConfig, TokenBucketError, TokenBucketLimiter,
};
use zeroize::Zeroizing;

use crate::trigger::{HookAdmission, HookPassGate};

/// One authenticated hook body may carry at most 1 MiB. The bytes are streamed
/// to a discard sink, never assembled, parsed, persisted, or forwarded.
pub const MAX_HOOK_BODY_BYTES: usize = 1_048_576;
/// An authenticated sender has ten seconds to finish the bounded body discard.
pub const HOOK_BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Once shutdown starts, the host gives every accepted connection ten seconds
/// to drain before it cancels the ingress server and returns a closed fault.
pub const HOOK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BASIC_USERNAME_BYTES: usize = 256;
const MAX_BASIC_PASSWORD_BYTES: usize = 4_096;
const MAX_BASIC_PAYLOAD_BYTES: usize = 6_000;

/// One closed, value-free hook-ingress startup or serving failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum HookIngressError {
    /// An authored hook trigger lacks its `path` or its `binding`.
    #[error("adapter.job.hook-configuration-trigger")]
    TriggerIncomplete,
    /// The job authors hooks but the runtime has no `hookIngress`.
    #[error("adapter.job.hook-configuration-ingress-missing")]
    IngressMissing,
    /// The runtime has a `hookIngress` but the job authors no hook.
    #[error("adapter.job.hook-configuration-ingress-unused")]
    IngressUnused,
    /// The authored hook bindings and the runtime `hookIngress` sources are
    /// not the same set.
    #[error("adapter.job.hook-configuration-binding")]
    BindingMismatch,
    /// Two authored hooks serve the same path.
    #[error("adapter.job.hook-configuration-path")]
    PathRepeated,
    /// The detail names the source, the runtime member, the secret reference
    /// and a closed cause with the fix; it never carries a secret value.
    #[error("adapter.job.hook-credential: {0}")]
    Credential(String),
    #[error("adapter.job.hook-rate-limit")]
    RateLimit,
    #[error("adapter.job.hook-bind")]
    Bind,
    #[error("adapter.job.hook-serve")]
    Serve,
    #[error("adapter.job.hook-shutdown-timeout")]
    ShutdownTimeout,
}

/// Check the exact authored-hook to runtime-source correspondence without
/// resolving a secret or opening a socket. `adapter-job check` uses this path.
pub fn validate_hook_runtime(
    job: &AdapterJob,
    runtime: &JobRuntimeConfig,
) -> Result<(), HookIngressError> {
    let authored = job
        .triggers
        .iter()
        .filter(|trigger| trigger.kind == "hook")
        .map(|trigger| {
            let path = trigger
                .path
                .as_deref()
                .ok_or(HookIngressError::TriggerIncomplete)?;
            let binding = trigger
                .binding
                .as_ref()
                .ok_or(HookIngressError::TriggerIncomplete)?;
            Ok((path, binding))
        })
        .collect::<Result<Vec<_>, HookIngressError>>()?;
    match (authored.is_empty(), runtime.hook_ingress.as_ref()) {
        (true, None) => return Ok(()),
        (true, Some(_)) => return Err(HookIngressError::IngressUnused),
        (false, None) => return Err(HookIngressError::IngressMissing),
        (false, Some(_)) => {}
    }
    let ingress = runtime
        .hook_ingress
        .as_ref()
        .ok_or(HookIngressError::IngressMissing)?;
    let authored_bindings = authored
        .iter()
        .map(|(_, binding)| (*binding).clone())
        .collect::<BTreeSet<_>>();
    let configured_bindings = ingress.sources.keys().cloned().collect::<BTreeSet<_>>();
    if authored_bindings != configured_bindings {
        return Err(HookIngressError::BindingMismatch);
    }
    Ok(())
}

/// Resolve immutable Basic credentials and rate limiters without opening the
/// hook socket. Absence is the default-off host behavior.
pub fn activate(
    job: &AdapterJob,
    runtime: &JobRuntimeConfig,
    resolver: &SecretResolver,
    gate: Arc<HookPassGate>,
) -> Result<Option<HookIngressPlan>, HookIngressError> {
    validate_hook_runtime(job, runtime)?;
    let Some(ingress) = runtime.hook_ingress.as_ref() else {
        return Ok(None);
    };
    let mut sources = BTreeMap::new();
    for trigger in job.triggers.iter().filter(|trigger| trigger.kind == "hook") {
        let path = trigger
            .path
            .as_ref()
            .ok_or(HookIngressError::TriggerIncomplete)?;
        let binding = trigger
            .binding
            .as_ref()
            .ok_or(HookIngressError::TriggerIncomplete)?;
        let config = ingress
            .sources
            .get(binding)
            .ok_or(HookIngressError::BindingMismatch)?;
        let source = HookSource {
            credential: BasicCredential::resolve(binding, config, resolver)?,
            limiter: TokenBucketLimiter::new(TokenBucketConfig {
                requests_per_minute: u32::try_from(config.requests_per_minute.get())
                    .map_err(|_| HookIngressError::RateLimit)?,
                burst: u32::try_from(config.burst.get())
                    .map_err(|_| HookIngressError::RateLimit)?,
            })
            .map_err(|_| HookIngressError::RateLimit)?,
        };
        if sources.insert(path.clone(), Arc::new(source)).is_some() {
            return Err(HookIngressError::PathRepeated);
        }
    }
    Ok(Some(HookIngressPlan {
        bind: ingress.listener.bind.socket_addr(),
        state: IngressState {
            sources: Arc::new(sources),
            gate,
        },
    }))
}

/// Resolve every hook credential and rate limiter without opening the socket,
/// so `check` and the loop start-up refuse a broken credential with its named
/// cause instead of the first sender seeing a bare 401.
pub fn preflight(
    job: &AdapterJob,
    runtime: &JobRuntimeConfig,
    resolver: &SecretResolver,
) -> Result<(), HookIngressError> {
    activate(job, runtime, resolver, Arc::new(HookPassGate::default())).map(|_| ())
}

/// An activated hook ingress whose secrets are captured but whose socket is
/// not open yet.
pub struct HookIngressPlan {
    bind: SocketAddr,
    state: IngressState,
}

impl HookIngressPlan {
    /// Bind the configured loopback listener before the pass loop starts.
    pub async fn bind(self) -> Result<HookIngressServer, HookIngressError> {
        let listener = tokio::net::TcpListener::bind(self.bind)
            .await
            .map_err(|_| HookIngressError::Bind)?;
        let router = Router::new()
            .fallback(any(receive_hook))
            .with_state(self.state);
        Ok(HookIngressServer { listener, router })
    }
}

/// One bound hook-ingress server.
pub struct HookIngressServer {
    listener: tokio::net::TcpListener,
    router: Router,
}

impl HookIngressServer {
    /// The actual address, including an ephemeral development port when the
    /// listener was configured with port zero.
    pub fn local_addr(&self) -> Result<SocketAddr, HookIngressError> {
        self.listener
            .local_addr()
            .map_err(|_| HookIngressError::Bind)
    }

    /// Serve until the host asks every companion task to shut down.
    pub async fn serve(
        self,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), HookIngressError> {
        self.serve_with_shutdown_timeout(shutdown, HOOK_SHUTDOWN_TIMEOUT)
            .await
    }

    async fn serve_with_shutdown_timeout(
        self,
        shutdown: impl Future<Output = ()> + Send + 'static,
        shutdown_timeout: Duration,
    ) -> Result<(), HookIngressError> {
        let (shutdown_started, shutdown_started_rx) = tokio::sync::oneshot::channel();
        let graceful_shutdown = async move {
            shutdown.await;
            let _ = shutdown_started.send(());
        };
        let server = std::future::IntoFuture::into_future(
            axum::serve(self.listener, self.router).with_graceful_shutdown(graceful_shutdown),
        );
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result.map_err(|_| HookIngressError::Serve),
            started = shutdown_started_rx => {
                started.map_err(|_| HookIngressError::Serve)?;
                tokio::time::timeout(shutdown_timeout, &mut server)
                    .await
                    .map_err(|_| HookIngressError::ShutdownTimeout)?
                    .map_err(|_| HookIngressError::Serve)
            }
        }
    }
}

const TRAILING_NEWLINE: &str = "the value ends with a newline, so the sender's credential would never match it; rewrite the secret without one, for example printf '%s' VALUE > FILE";

fn resolve_member(
    source: &str,
    member: &str,
    reference: &str,
    resolver: &SecretResolver,
) -> Result<ProtectedSecret, HookIngressError> {
    resolver.resolve(reference).map_err(|error| {
        let cause = match error {
            SecretError::Unavailable if reference.starts_with("secret:env/") => {
                "the environment variable is not set"
            }
            SecretError::Unavailable => "the secret file is missing",
            SecretError::UnsafeFile => {
                "the secret file must be a regular file with mode 0400 or 0600"
            }
            SecretError::Read => "the secret file could not be read",
            SecretError::InvalidValue => "the secret is empty or contains a NUL byte",
            SecretError::ProviderDisabled => {
                "the reference uses a secret provider that the runtime does not enable"
            }
            SecretError::InvalidReference | SecretError::InvalidProviderConfiguration => {
                "the secret reference or provider configuration is invalid"
            }
        };
        credential_refusal(source, member, reference, cause)
    })
}

fn credential_refusal(
    source: &str,
    member: &str,
    reference: &str,
    cause: &str,
) -> HookIngressError {
    HookIngressError::Credential(format!(
        "hookIngress.sources.{source}.{member} ({reference}): {cause}"
    ))
}

struct BasicCredential {
    username: ProtectedSecret,
    password: ProtectedSecret,
}

impl std::fmt::Debug for BasicCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BasicCredential([REDACTED])")
    }
}

impl BasicCredential {
    fn resolve(
        source: &str,
        config: &HookSourceConfig,
        resolver: &SecretResolver,
    ) -> Result<Self, HookIngressError> {
        let username = resolve_member(
            source,
            "usernameRef",
            config.username_ref.as_str(),
            resolver,
        )?;
        let password = resolve_member(
            source,
            "passwordRef",
            config.password_ref.as_str(),
            resolver,
        )?;
        let refuse = |member: &str, reference: &str, cause: &str| {
            Err(credential_refusal(source, member, reference, cause))
        };
        if username.len() > MAX_BASIC_USERNAME_BYTES {
            return refuse(
                "usernameRef",
                config.username_ref.as_str(),
                "the username is longer than 256 bytes",
            );
        }
        if username.expose_secret().last() == Some(&b'\n') {
            return refuse(
                "usernameRef",
                config.username_ref.as_str(),
                TRAILING_NEWLINE,
            );
        }
        if username
            .expose_secret()
            .iter()
            .any(|byte| *byte == b':' || byte.is_ascii_control())
        {
            return refuse(
                "usernameRef",
                config.username_ref.as_str(),
                "the username contains ':' or a control character, which Basic authentication cannot carry",
            );
        }
        if password.expose_secret().last() == Some(&b'\n') {
            return refuse(
                "passwordRef",
                config.password_ref.as_str(),
                TRAILING_NEWLINE,
            );
        }
        if password.len() > MAX_BASIC_PASSWORD_BYTES {
            return refuse(
                "passwordRef",
                config.password_ref.as_str(),
                "the password is longer than 4096 bytes",
            );
        }
        Ok(Self { username, password })
    }

    fn authenticates(&self, authorization: &[u8]) -> bool {
        if authorization.len() > MAX_BASIC_PAYLOAD_BYTES + 6 {
            return false;
        }
        let Some((scheme, payload)) = split_once(authorization, b' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case(b"Basic")
            || payload.is_empty()
            || payload.iter().any(u8::is_ascii_whitespace)
            || payload.len() > MAX_BASIC_PAYLOAD_BYTES
        {
            return false;
        }
        let Ok(mut decoded) = STANDARD.decode(payload).map(Zeroizing::new) else {
            return false;
        };
        let canonical = Zeroizing::new(STANDARD.encode(decoded.as_slice()));
        if canonical.as_bytes() != payload {
            return false;
        }
        let Some(colon) = decoded.iter().position(|byte| *byte == b':') else {
            return false;
        };
        let password = Zeroizing::new(decoded.split_off(colon + 1));
        decoded.truncate(colon);
        let username_matches = constant_time_eq(decoded.as_slice(), self.username.expose_secret());
        let password_matches = constant_time_eq(password.as_slice(), self.password.expose_secret());
        username_matches & password_matches
    }
}

fn split_once(bytes: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    let at = bytes.iter().position(|byte| *byte == separator)?;
    Some((&bytes[..at], &bytes[at + 1..]))
}

struct HookSource {
    credential: BasicCredential,
    limiter: TokenBucketLimiter,
}

#[derive(Clone)]
struct IngressState {
    sources: Arc<BTreeMap<String, Arc<HookSource>>>,
    gate: Arc<HookPassGate>,
}

async fn receive_hook(State(state): State<IngressState>, request: Request<Body>) -> Response<Body> {
    receive_hook_until(
        State(state),
        request,
        tokio::time::sleep(HOOK_BODY_READ_TIMEOUT),
    )
    .await
}

async fn receive_hook_until(
    State(state): State<IngressState>,
    request: Request<Body>,
    body_deadline: impl Future<Output = ()>,
) -> Response<Body> {
    let Some(source) = state.sources.get(request.uri().path()).cloned() else {
        return response(StatusCode::NOT_FOUND, "adapter.job.hook-not-found", None);
    };
    if request.method() != Method::POST {
        return response(
            StatusCode::METHOD_NOT_ALLOWED,
            "adapter.job.hook-method",
            None,
        );
    }
    if !authenticated(request.headers(), &source.credential) {
        return response(
            StatusCode::UNAUTHORIZED,
            "adapter.job.hook-unauthenticated",
            None,
        );
    }
    let retry_after = match source.limiter.check("source", 1).await {
        Ok(()) => None,
        Err(TokenBucketError::Exceeded { retry_after }) => Some(retry_after),
        Err(
            TokenBucketError::Configuration
            | TokenBucketError::Capacity
            | TokenBucketError::CostExceedsBurst,
        ) => {
            return response(
                StatusCode::SERVICE_UNAVAILABLE,
                "adapter.job.hook-unavailable",
                None,
            )
        }
    };
    if let Some(retry_after) = retry_after {
        return response(
            StatusCode::TOO_MANY_REQUESTS,
            "adapter.job.hook-rate-limited",
            Some(retry_after.as_secs_f64().ceil().max(1.0) as u64),
        );
    }
    let discarded = tokio::select! {
        biased;
        result = discard_body(request.into_body()) => Some(result),
        () = body_deadline => None,
    };
    match discarded {
        None => {
            return response(
                StatusCode::REQUEST_TIMEOUT,
                "adapter.job.hook-body-timeout",
                None,
            )
        }
        Some(Ok(_)) => {}
        Some(Err(HookRefusal::BodyTooLarge)) => {
            return response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "adapter.job.hook-body-too-large",
                None,
            )
        }
        Some(Err(HookRefusal::BodyUnreadable)) => {
            return response(
                StatusCode::BAD_REQUEST,
                "adapter.job.hook-body-unreadable",
                None,
            )
        }
    }
    match state.gate.handle_hook() {
        HookAdmission::Started => response(StatusCode::ACCEPTED, "started", None),
        HookAdmission::Joined => response(StatusCode::ACCEPTED, "joined", None),
    }
}

fn authenticated(headers: &HeaderMap, credential: &BasicCredential) -> bool {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    credential.authenticates(value.as_bytes())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HookRefusal {
    BodyTooLarge,
    BodyUnreadable,
}

async fn discard_body(body: Body) -> Result<usize, HookRefusal> {
    let mut stream = body.into_data_stream();
    let mut total = 0_usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| HookRefusal::BodyUnreadable)?;
        total = total
            .checked_add(chunk.len())
            .ok_or(HookRefusal::BodyTooLarge)?;
        if total > MAX_HOOK_BODY_BYTES {
            return Err(HookRefusal::BodyTooLarge);
        }
    }
    Ok(total)
}

fn response(status: StatusCode, code: &'static str, retry_after: Option<u64>) -> Response<Body> {
    let body = match code {
        "started" => r#"{"status":"started"}"#,
        "joined" => r#"{"status":"joined"}"#,
        "adapter.job.hook-not-found" => r#"{"code":"adapter.job.hook-not-found"}"#,
        "adapter.job.hook-method" => r#"{"code":"adapter.job.hook-method"}"#,
        "adapter.job.hook-unauthenticated" => r#"{"code":"adapter.job.hook-unauthenticated"}"#,
        "adapter.job.hook-rate-limited" => r#"{"code":"adapter.job.hook-rate-limited"}"#,
        "adapter.job.hook-body-too-large" => r#"{"code":"adapter.job.hook-body-too-large"}"#,
        "adapter.job.hook-body-unreadable" => r#"{"code":"adapter.job.hook-body-unreadable"}"#,
        "adapter.job.hook-body-timeout" => r#"{"code":"adapter.job.hook-body-timeout"}"#,
        _ => r#"{"code":"adapter.job.hook-unavailable"}"#,
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"adapter-job-hook\", charset=\"UTF-8\""),
        );
    }
    if let Some(seconds) = retry_after {
        let value = HeaderValue::from_str(&seconds.to_string())
            .expect("an unsigned decimal is a valid HTTP header value");
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use registry_platform_config::{SecretProvider, SecretResolver};
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    async fn test_server(
        path: &str,
        burst: u32,
    ) -> (
        SocketAddr,
        Arc<HookPassGate>,
        tokio::task::JoinHandle<Result<(), std::io::Error>>,
    ) {
        let (_root, resolver) = secret_resolver();
        let source = Arc::new(HookSource {
            credential: BasicCredential::resolve("kobo-submissions", &source_config(), &resolver)
                .expect("the credential resolves"),
            limiter: TokenBucketLimiter::new(TokenBucketConfig {
                requests_per_minute: 60,
                burst,
            })
            .expect("a bounded rate limit"),
        });
        let gate = Arc::new(HookPassGate::default());
        let state = IngressState {
            sources: Arc::new(BTreeMap::from([(path.to_string(), source)])),
            gate: Arc::clone(&gate),
        };
        let router = Router::new().fallback(any(receive_hook)).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback test listener");
        let address = listener.local_addr().expect("the bound address");
        let task = tokio::spawn(async move { axum::serve(listener, router).await });
        (address, gate, task)
    }

    fn basic_header(password: &str) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("kobo-webhook:{password}"))
        )
    }

    fn secret_resolver() -> (tempfile::TempDir, SecretResolver) {
        let root = tempfile::tempdir().expect("a secret root");
        for (name, value) in [
            ("username", b"kobo-webhook".as_slice()),
            ("password", b"correct horse battery staple".as_slice()),
        ] {
            let path = root.path().join(name);
            std::fs::write(&path, value).expect("write a synthetic secret");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("confine the synthetic secret");
        }
        let resolver =
            SecretResolver::new([SecretProvider::File], root.path()).expect("a file-only resolver");
        (root, resolver)
    }

    fn source_config() -> registry_adapter_engine::job_sources::HookSourceConfig {
        serde_json::from_value(serde_json::json!({
            "usernameRef": "secret:file/username",
            "passwordRef": "secret:file/password",
            "requestsPerMinute": 60,
            "burst": 2
        }))
        .expect("a hook source config")
    }

    fn hook_example() -> (AdapterJob, JobRuntimeConfig) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/examples/kobotoolbox-job");
        let (job, _bytes) = registry_adapter_engine::load::read_artifact::<AdapterJob>(
            &root.join("job.hook.yaml"),
            registry_adapter_core::ADAPTER_JOB_KIND,
            registry_adapter_core::ADAPTER_JOB_API_VERSION,
        )
        .expect("the maintained hook job reads");
        let runtime = JobRuntimeConfig::load(&root.join("job-runtime.hook.example.yaml"))
            .expect("the maintained hook runtime reads");
        (job, runtime)
    }

    fn hook_trigger(index: usize, job: &mut AdapterJob) -> &mut registry_adapter_core::JobTrigger {
        job.triggers
            .iter_mut()
            .filter(|trigger| trigger.kind == "hook")
            .nth(index)
            .expect("the example declares the hook trigger")
    }

    /// Each way the authored hooks and the runtime hookIngress disagree
    /// refuses under its own closed code.
    #[test]
    fn each_hook_configuration_disagreement_has_its_own_code() {
        let (job, runtime) = hook_example();
        assert_eq!(validate_hook_runtime(&job, &runtime), Ok(()));

        let mut without_ingress = hook_example().1;
        without_ingress.hook_ingress = None;
        assert_eq!(
            validate_hook_runtime(&job, &without_ingress),
            Err(HookIngressError::IngressMissing)
        );

        let (mut without_hooks, runtime) = hook_example();
        without_hooks
            .triggers
            .retain(|trigger| trigger.kind != "hook");
        assert_eq!(
            validate_hook_runtime(&without_hooks, &runtime),
            Err(HookIngressError::IngressUnused)
        );

        let (mut pathless, runtime) = hook_example();
        hook_trigger(0, &mut pathless).path = None;
        assert_eq!(
            validate_hook_runtime(&pathless, &runtime),
            Err(HookIngressError::TriggerIncomplete)
        );
        let (mut unbound, runtime) = hook_example();
        hook_trigger(0, &mut unbound).binding = None;
        assert_eq!(
            validate_hook_runtime(&unbound, &runtime),
            Err(HookIngressError::TriggerIncomplete)
        );

        let (mut renamed, runtime) = hook_example();
        hook_trigger(0, &mut renamed).binding = Some("another-source".parse().expect("a local id"));
        assert_eq!(
            validate_hook_runtime(&renamed, &runtime),
            Err(HookIngressError::BindingMismatch)
        );
    }

    #[test]
    fn two_hooks_on_one_path_refuse_under_the_path_code() {
        let (mut job, mut runtime) = hook_example();
        let mut second = hook_trigger(0, &mut job).clone();
        second.binding = Some("second-source".parse().expect("a local id"));
        job.triggers.push(second);
        let ingress = runtime.hook_ingress.as_mut().expect("the example hooks");
        for config in ingress.sources.values_mut() {
            *config = source_config();
        }
        ingress.sources.insert(
            "second-source".parse().expect("a local id"),
            source_config(),
        );
        let (_root, resolver) = secret_resolver();
        assert_eq!(
            activate(&job, &runtime, &resolver, Arc::new(HookPassGate::default())).err(),
            Some(HookIngressError::PathRepeated)
        );
    }

    #[test]
    fn the_hook_configuration_codes_are_closed_and_value_free() {
        for (error, code) in [
            (
                HookIngressError::TriggerIncomplete,
                "adapter.job.hook-configuration-trigger",
            ),
            (
                HookIngressError::IngressMissing,
                "adapter.job.hook-configuration-ingress-missing",
            ),
            (
                HookIngressError::IngressUnused,
                "adapter.job.hook-configuration-ingress-unused",
            ),
            (
                HookIngressError::BindingMismatch,
                "adapter.job.hook-configuration-binding",
            ),
            (
                HookIngressError::PathRepeated,
                "adapter.job.hook-configuration-path",
            ),
        ] {
            assert_eq!(error.to_string(), code);
        }
    }

    #[test]
    fn basic_authentication_accepts_only_the_exact_canonical_pair() {
        let (_root, resolver) = secret_resolver();
        let credential = BasicCredential::resolve("kobo-submissions", &source_config(), &resolver)
            .expect("the credential resolves");
        let exact = format!(
            "Basic {}",
            STANDARD.encode(b"kobo-webhook:correct horse battery staple")
        );
        assert!(credential.authenticates(exact.as_bytes()));
        for refused in [
            String::new(),
            "Bearer token".to_string(),
            "Basic !!!".to_string(),
            format!("Basic {}", STANDARD.encode(b"kobo-webhook:wrong")),
            format!(
                "Basic {}",
                STANDARD.encode(b"wrong:correct horse battery staple")
            ),
        ] {
            assert!(!credential.authenticates(refused.as_bytes()), "{refused:?}");
        }
        assert_eq!(format!("{credential:?}"), "BasicCredential([REDACTED])");
    }

    #[test]
    fn basic_credential_resolution_refuses_ambiguous_or_overbound_values() {
        let root = tempfile::tempdir().expect("a secret root");
        for (username, password) in [
            (b"name:with-colon".to_vec(), b"password".to_vec()),
            (b"name".to_vec(), vec![b'p'; MAX_BASIC_PASSWORD_BYTES + 1]),
        ] {
            for (name, value) in [
                ("username", username.as_slice()),
                ("password", password.as_slice()),
            ] {
                let path = root.path().join(name);
                std::fs::write(&path, value).expect("write a synthetic secret");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("confine the synthetic secret");
            }
            let resolver = SecretResolver::new([SecretProvider::File], root.path())
                .expect("a file-only resolver");
            assert!(
                BasicCredential::resolve("kobo-submissions", &source_config(), &resolver).is_err()
            );
        }
    }

    fn refusal_for(files: &[(&str, &[u8], u32)]) -> String {
        let root = tempfile::tempdir().expect("a secret root");
        for (name, value, mode) in files {
            let path = root.path().join(name);
            std::fs::write(&path, value).expect("write a synthetic secret");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(*mode))
                .expect("set the synthetic secret mode");
        }
        let resolver =
            SecretResolver::new([SecretProvider::File], root.path()).expect("a file-only resolver");
        BasicCredential::resolve("kobo-submissions", &source_config(), &resolver)
            .expect_err("the credential is refused")
            .to_string()
    }

    #[test]
    fn a_missing_credential_file_names_the_member_the_reference_and_the_fix() {
        let message = refusal_for(&[("username", b"kobo-webhook", 0o600)]);
        assert!(
            message.starts_with("adapter.job.hook-credential: "),
            "{message}"
        );
        assert!(
            message.contains("hookIngress.sources.kobo-submissions.passwordRef"),
            "{message}"
        );
        assert!(message.contains("secret:file/password"), "{message}");
        assert!(message.contains("missing"), "{message}");
    }

    #[test]
    fn an_unsafe_credential_file_names_the_required_mode() {
        let message = refusal_for(&[
            ("username", b"kobo-webhook", 0o600),
            ("password", b"synthetic-password", 0o644),
        ]);
        assert!(
            message.contains("hookIngress.sources.kobo-submissions.passwordRef"),
            "{message}"
        );
        assert!(message.contains("0400 or 0600"), "{message}");
    }

    #[test]
    fn a_trailing_newline_is_refused_with_the_fix_not_left_to_fail_as_401() {
        let message = refusal_for(&[
            ("username", b"kobo-webhook", 0o600),
            ("password", b"synthetic-password\n", 0o600),
        ]);
        assert!(
            message.contains("hookIngress.sources.kobo-submissions.passwordRef"),
            "{message}"
        );
        assert!(message.contains("secret:file/password"), "{message}");
        assert!(message.contains("ends with a newline"), "{message}");
        assert!(message.contains("printf '%s'"), "{message}");
        assert!(!message.contains("synthetic-password"), "{message}");
    }

    #[test]
    fn a_username_with_a_colon_is_refused_with_its_member() {
        let message = refusal_for(&[
            ("username", b"kobo:webhook", 0o600),
            ("password", b"synthetic-password", 0o600),
        ]);
        assert!(
            message.contains("hookIngress.sources.kobo-submissions.usernameRef"),
            "{message}"
        );
        assert!(message.contains("':'"), "{message}");
        assert!(!message.contains("kobo:webhook"), "{message}");
    }

    #[tokio::test]
    async fn bounded_body_discard_never_returns_or_parses_the_body() {
        let body = axum::body::Body::from(vec![b'x'; 1024]);
        assert_eq!(discard_body(body).await, Ok(1024));
        let over = axum::body::Body::from(vec![b'x'; MAX_HOOK_BODY_BYTES + 1]);
        assert_eq!(discard_body(over).await, Err(HookRefusal::BodyTooLarge));
    }

    #[tokio::test]
    async fn real_http_ingress_authenticates_before_rate_and_coalesces_duplicates() {
        let (address, _gate, task) = test_server("/hooks/kobo", 2).await;
        let client = reqwest::Client::new();
        let url = format!("http://{address}/hooks/kobo");

        let unauthenticated = client
            .post(&url)
            .header(AUTHORIZATION, basic_header("wrong"))
            .body("untrusted-body-marker")
            .send()
            .await
            .expect("the loopback request completes");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthenticated.text().await.expect("a static response"),
            r#"{"code":"adapter.job.hook-unauthenticated"}"#
        );

        for expected in [r#"{"status":"started"}"#, r#"{"status":"joined"}"#] {
            let accepted = client
                .post(&url)
                .header(AUTHORIZATION, basic_header("correct horse battery staple"))
                .body("untrusted-body-marker")
                .send()
                .await
                .expect("the loopback request completes");
            assert_eq!(accepted.status(), StatusCode::ACCEPTED);
            assert_eq!(accepted.text().await.expect("a static response"), expected);
        }

        let limited = client
            .post(&url)
            .header(AUTHORIZATION, basic_header("correct horse battery staple"))
            .send()
            .await
            .expect("the loopback request completes");
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers()[RETRY_AFTER], "1");
        task.abort();
        assert!(task
            .await
            .expect_err("the test server was explicitly cancelled")
            .is_cancelled());
    }

    #[tokio::test]
    async fn oversized_body_is_refused_before_it_can_start_a_pass() {
        let (address, gate, task) = test_server("/hooks/kobo", 2).await;
        let response = reqwest::Client::new()
            .post(format!("http://{address}/hooks/kobo"))
            .header(AUTHORIZATION, basic_header("correct horse battery staple"))
            .body(vec![b'x'; MAX_HOOK_BODY_BYTES + 1])
            .send()
            .await
            .expect("the loopback request completes");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(gate.handle_hook(), HookAdmission::Started);
        task.abort();
        assert!(task
            .await
            .expect_err("the test server was explicitly cancelled")
            .is_cancelled());
    }

    #[tokio::test]
    async fn authenticated_body_that_stalls_is_timed_out_without_waking_a_pass() {
        let (_root, resolver) = secret_resolver();
        let source = Arc::new(HookSource {
            credential: BasicCredential::resolve("kobo-submissions", &source_config(), &resolver)
                .expect("the credential resolves"),
            limiter: TokenBucketLimiter::new(TokenBucketConfig {
                requests_per_minute: 60,
                burst: 2,
            })
            .expect("a bounded rate limit"),
        });
        let gate = Arc::new(HookPassGate::default());
        let state = IngressState {
            sources: Arc::new(BTreeMap::from([("/hooks/kobo".to_string(), source)])),
            gate: Arc::clone(&gate),
        };
        let stream = futures::stream::once(async {
            Ok::<_, std::convert::Infallible>(axum::body::Bytes::from_static(b"{"))
        })
        .chain(futures::stream::pending());
        let request = Request::builder()
            .method(Method::POST)
            .uri("/hooks/kobo")
            .header(AUTHORIZATION, basic_header("correct horse battery staple"))
            .body(Body::from_stream(stream))
            .expect("a streaming hook request");

        let response = receive_hook_until(State(state), request, std::future::ready(())).await;
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("the static timeout response reads");
        assert_eq!(
            body.as_ref(),
            br#"{"code":"adapter.job.hook-body-timeout"}"#
        );
        assert_eq!(gate.handle_hook(), HookAdmission::Started);
    }

    #[tokio::test]
    async fn partial_request_head_cannot_hold_graceful_shutdown_past_the_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback test listener");
        let address = listener.local_addr().expect("the bound address");
        let server = HookIngressServer {
            listener,
            router: Router::new().fallback(any(|| async { StatusCode::NOT_FOUND })),
        };
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(server.serve_with_shutdown_timeout(
            async move {
                let _ = shutdown_rx.await;
            },
            Duration::from_millis(25),
        ));

        let mut partial = std::net::TcpStream::connect(address)
            .expect("a real loopback client connects to the hook listener");
        partial
            .write_all(b"POST /hooks/kobo HTTP/1.1\r\nHost: loopback\r\nX-Stalled: ")
            .expect("write an intentionally incomplete request head");
        let barrier = reqwest::get(format!("http://{address}/accepted-after-partial"))
            .await
            .expect("the accept loop continues past the partial connection");
        assert_eq!(barrier.status(), StatusCode::NOT_FOUND);
        barrier
            .bytes()
            .await
            .expect("the accept-loop barrier response drains");

        shutdown.send(()).expect("signal hook-server shutdown");
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the outer hook shutdown bound completes")
            .expect("the hook server task joins");
        assert_eq!(result, Err(HookIngressError::ShutdownTimeout));
        drop(partial);
    }

    #[tokio::test]
    async fn real_router_preserves_unreserved_punctuation_and_never_decodes_unicode_paths() {
        let accepted_path = "/hooks/kobo-submissions_v1.~ready";
        let (address, _gate, task) = test_server(accepted_path, 2).await;
        let client = reqwest::Client::new();
        let authorization = basic_header("correct horse battery staple");

        let accepted = client
            .post(format!("http://{address}{accepted_path}"))
            .header(AUTHORIZATION, &authorization)
            .send()
            .await
            .expect("the unreserved path reaches the real router");
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);

        let encoded_unicode = client
            .post(format!("http://{address}/hooks/caf%C3%A9"))
            .header(AUTHORIZATION, authorization)
            .send()
            .await
            .expect("the encoded path reaches the real router");
        assert_eq!(encoded_unicode.status(), StatusCode::NOT_FOUND);

        task.abort();
        assert!(task
            .await
            .expect_err("the test server was explicitly cancelled")
            .is_cancelled());
    }
}
