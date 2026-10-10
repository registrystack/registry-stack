// SPDX-License-Identifier: Apache-2.0
//! Bounded product bindings over maintained Registry clients.

use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use registry_breg_client::{
    BRegRecordOptions, BaseRegistryClient, BaseRegistryClientConfig, BaseRegistryClientError,
};
use registry_casework_client::{CaseworkClient, CaseworkClientConfig, CaseworkTaskAssertionSource};
use registry_messaging_client::{
    MessagingClient, MessagingClientConfig, MessagingClientError, ProblemCode, SubmitMessageRequest,
};
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::{
    client::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenError, TokenProvider},
    ExchangeAuthorization, ExchangeContext, FetchUrlPolicy,
};
use registry_scheduling_client::{
    CreateAppointmentRequest, ProblemCode as SchedulingProblemCode, SchedulingAuth,
    SchedulingClient, SchedulingClientConfig, SchedulingClientError,
};
use serde::Deserialize;
use url::Url;
use uuid::Uuid;

use crate::{
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation, ReconciliationOutcome},
    PocError, Result,
};

const FILE_BOUND: u64 = 65_536;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

pub use crate::runtime::{
    AuthorizationConfig, ConnectionConfig, Product, RuntimeConfig, TaskAuthorityConfig,
};

enum Connection {
    Breg {
        client: Box<BaseRegistryClient>,
        options: BRegRecordOptions,
        profile: String,
    },
    BregTask(Box<TaskConnection>),
    Scheduling(Box<SchedulingConnection>),
    Messaging {
        client: MessagingClient,
        tokens: Arc<PrivateKeyJwt>,
    },
    External(Box<crate::external_http::ExternalHttpConnection>),
}

struct SchedulingConnection {
    client: SchedulingClient,
    authorization: AuthorizationConfig,
    key: PrivateJwk,
    standing: Option<Arc<PrivateKeyJwt>>,
    observation: Option<Arc<PrivateKeyJwt>>,
}

struct TaskConnection {
    base_url: Url,
    options: BRegRecordOptions,
    authorization: AuthorizationConfig,
    key: PrivateJwk,
}

pub struct HttpAdapters {
    connections: BTreeMap<String, Connection>,
    digest: String,
    config: RuntimeConfig,
}

fn config_error() -> PocError {
    PocError::new(
        "adapter.configuration",
        "product binding or secret-file configuration is invalid",
    )
}

// Destinations are explicit, reviewed deployment bindings. Institutional peers
// may use private HTTPS networks; all token requests remain DNS-pinned and
// reject metadata addresses. Cleartext remains numeric loopback only.
fn configured_endpoint_policy(endpoint: &Url) -> FetchUrlPolicy {
    if endpoint.scheme() == "http" {
        FetchUrlPolicy::dev()
    } else {
        FetchUrlPolicy {
            allowed_schemes: vec!["https".into()],
            allow_localhost: true,
            allow_http_private_network: false,
            deny_private_ranges: false,
            deny_cloud_metadata: true,
        }
    }
}

fn tokens(
    auth: &AuthorizationConfig,
    key: PrivateJwk,
    resource: &str,
    scopes: &[String],
) -> std::result::Result<PrivateKeyJwt, TokenError> {
    let mut config = PrivateKeyJwtConfig::new(auth.token_endpoint.clone(), &auth.client_id, key)
        .with_resource(resource)
        .with_scopes(scopes.iter().cloned())
        .with_fetch_url_policy(configured_endpoint_policy(&auth.token_endpoint))
        .with_request_timeout(REQUEST_TIMEOUT)
        .with_connect_timeout(Duration::from_secs(1));
    if let Some(audience) = &auth.client_assertion_audience {
        config = config.with_audience(audience);
    }
    PrivateKeyJwt::new(config)
}

fn breg_client(
    url: Url,
    tokens: Arc<dyn TokenProvider>,
) -> std::result::Result<BaseRegistryClient, BaseRegistryClientError> {
    BaseRegistryClient::new(
        BaseRegistryClientConfig::new(url)
            .with_token_provider(tokens)
            .with_max_mutation_retries(0)
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_connect_timeout(Duration::from_secs(1))
            .with_max_response_bytes(FILE_BOUND),
    )
}

impl HttpAdapters {
    pub fn load(path: &Path) -> Result<Self> {
        Self::new(&RuntimeConfig::load(path)?)
    }

    pub fn new(config: &RuntimeConfig) -> Result<Self> {
        config.validate()?;
        let secrets = config
            .secret_providers
            .resolver()
            .map_err(|_| config_error())?;
        let mut connections = BTreeMap::new();
        for (name, binding) in config.connections.clone() {
            let auth = binding.authorization;
            let key_bytes = secrets
                .resolve_reference(&auth.signing_key_ref)
                .map_err(|_| config_error())?;
            let key_text =
                std::str::from_utf8(key_bytes.expose_secret()).map_err(|_| config_error())?;
            let key = PrivateJwk::parse(key_text).map_err(|_| config_error())?;
            let observation = if let Some(observation) = &binding.observation_authorization {
                let bytes = secrets
                    .resolve_reference(&observation.signing_key_ref)
                    .map_err(|_| config_error())?;
                let text =
                    std::str::from_utf8(bytes.expose_secret()).map_err(|_| config_error())?;
                let observation_key = PrivateJwk::parse(text).map_err(|_| config_error())?;
                Some(Arc::new(
                    tokens(
                        observation,
                        observation_key,
                        &observation.resource,
                        &observation.scopes,
                    )
                    .map_err(|_| config_error())?,
                ))
            } else {
                None
            };
            let connection = match binding.product {
                Product::Breg => {
                    let profile = binding.profile.ok_or_else(config_error)?;
                    let options = BRegRecordOptions::default()
                        .access_profile(&profile)
                        .map_err(|_| config_error())?;
                    if auth.task_authority.is_some() {
                        Connection::BregTask(Box::new(TaskConnection {
                            base_url: binding.base_url,
                            options,
                            authorization: auth,
                            key,
                        }))
                    } else {
                        let tokens = Arc::new(
                            tokens(&auth, key, &auth.resource, &auth.scopes)
                                .map_err(|_| config_error())?,
                        );
                        Connection::Breg {
                            client: Box::new(
                                breg_client(binding.base_url, tokens)
                                    .map_err(|_| config_error())?,
                            ),
                            options,
                            profile,
                        }
                    }
                }
                Product::Scheduling => {
                    let standing = if auth.task_authority.is_none() {
                        Some(Arc::new(
                            tokens(&auth, key.clone(), &auth.resource, &auth.scopes)
                                .map_err(|_| config_error())?,
                        ))
                    } else {
                        None
                    };
                    let client = SchedulingClient::new(
                        SchedulingClientConfig::new(binding.base_url)
                            .with_max_mutation_retries(0)
                            .with_request_timeout(REQUEST_TIMEOUT)
                            .with_connect_timeout(Duration::from_secs(1))
                            .with_max_response_bytes(FILE_BOUND),
                    )
                    .map_err(|_| config_error())?;
                    Connection::Scheduling(Box::new(SchedulingConnection {
                        client,
                        authorization: auth,
                        key,
                        standing,
                        observation,
                    }))
                }
                Product::Messaging => {
                    let tokens = Arc::new(
                        tokens(&auth, key, &auth.resource, &auth.scopes)
                            .map_err(|_| config_error())?,
                    );
                    let client = MessagingClient::new(
                        MessagingClientConfig::new(binding.base_url)
                            .with_max_mutation_retries(0)
                            .with_request_timeout(REQUEST_TIMEOUT)
                            .with_connect_timeout(Duration::from_secs(1))
                            .with_max_response_bytes(FILE_BOUND),
                    )
                    .map_err(|_| config_error())?;
                    Connection::Messaging { client, tokens }
                }
            };
            connections.insert(name, connection);
        }
        for (name, binding) in &config.external_http_connections {
            let provider: Option<Arc<dyn TokenProvider>> = match &binding.authorization {
                Some(auth) => {
                    let key_bytes = secrets
                        .resolve_reference(&auth.signing_key_ref)
                        .map_err(|_| config_error())?;
                    let key_text = std::str::from_utf8(key_bytes.expose_secret())
                        .map_err(|_| config_error())?;
                    let key = PrivateJwk::parse(key_text).map_err(|_| config_error())?;
                    Some(Arc::new(
                        tokens(auth, key, &auth.resource, &auth.scopes)
                            .map_err(|_| config_error())?,
                    ))
                }
                None => None,
            };
            let connection = crate::external_http::ExternalHttpConnection::new(binding, provider)?;
            connections.insert(name.clone(), Connection::External(Box::new(connection)));
        }
        let digest = config.binding_digest()?;
        Ok(Self {
            connections,
            digest,
            config: config.clone(),
        })
    }
}

pub(crate) fn refused(code: &str) -> CallOutcome {
    CallOutcome::Refused {
        code: code.to_owned(),
    }
}
pub(crate) fn retryable(code: &str) -> CallOutcome {
    CallOutcome::Retryable {
        code: code.to_owned(),
    }
}

pub(crate) fn token_failure(error: &TokenError) -> CallOutcome {
    match error {
        TokenError::Transport { .. } | TokenError::Unavailable => {
            retryable("credential-unavailable")
        }
        TokenError::Protocol {
            status: 408 | 429 | 500..=599,
        } => retryable("credential-unavailable"),
        _ => refused("credential-refused"),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadRequest {
    collection: String,
    record_id: String,
    #[serde(default)]
    grant: Option<GrantReference>,
}

/// An approval reference, never an assertion or bearer credential. The shared
/// Casework source requires the signed authority's original deadline to match.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantReference {
    id: Uuid,
    expires_at: i64,
}

fn task_provider(
    auth: &AuthorizationConfig,
    key: &PrivateJwk,
    grant: &GrantReference,
) -> std::result::Result<ExchangeAuthorization, CallOutcome> {
    let authority = auth
        .task_authority
        .as_ref()
        .ok_or_else(|| refused("invalid-command"))?;
    let context = ExchangeContext::grant(
        &authority.issuer,
        &authority.subject,
        &authority.exchange_audience,
        grant.id.to_string(),
        grant.expires_at,
        grant.id.to_string(),
    )
    .map_err(|error| token_failure(&error))?;
    let bootstrap = tokens(
        auth,
        key.clone(),
        &authority.bootstrap_resource,
        &["casework:grants:assert".to_owned()],
    )
    .map_err(|error| token_failure(&error))?;
    let casework = CaseworkClient::new(
        CaseworkClientConfig::new(authority.base_url.clone())
            .with_max_mutation_retries(0)
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_connect_timeout(Duration::from_secs(1))
            .with_max_response_bytes(FILE_BOUND),
    )
    .map_err(|_| refused("credential-configuration"))?;
    let source = CaseworkTaskAssertionSource::new(
        casework,
        bootstrap,
        grant.id,
        &authority.bootstrap_resource,
    )
    .map_err(|error| token_failure(&error))?;
    let exchange = tokens(auth, key.clone(), &auth.resource, &auth.scopes)
        .map_err(|error| token_failure(&error))?;
    // Reacquire authority for every durable attempt, including after a
    // restart. There is no standing-service fallback or cached task bearer.
    let provider = ExchangeAuthorization::from_authority(exchange, context, Arc::new(source))
        .map_err(|error| token_failure(&error))?
        .with_fetch_url_policy(configured_endpoint_policy(&auth.token_endpoint));
    Ok(provider)
}

impl TaskConnection {
    fn client(
        &self,
        grant: &GrantReference,
    ) -> std::result::Result<BaseRegistryClient, CallOutcome> {
        let provider = task_provider(&self.authorization, &self.key, grant)?;
        breg_client(self.base_url.clone(), Arc::new(provider))
            .map_err(|_| refused("credential-configuration"))
    }
}

async fn read_record(
    client: &BaseRegistryClient,
    options: &BRegRecordOptions,
    input: &ReadRequest,
) -> CallOutcome {
    match client
        .get_record(&input.collection, &input.record_id, options)
        .await
    {
        Ok(answer) => match serde_json::to_value(answer.value) {
            Ok(value) => CallOutcome::Success(value),
            Err(_) => refused("invalid-response"),
        },
        Err(BaseRegistryClientError::Token(error)) => token_failure(&error),
        Err(BaseRegistryClientError::Transport { .. }) => retryable("transport-unavailable"),
        Err(error) if error.status() == Some(429) => retryable("rate-limited"),
        Err(BaseRegistryClientError::Problem {
            status: 401 | 403, ..
        }) => refused("product-forbidden"),
        Err(BaseRegistryClientError::Problem { status: 404, .. }) => refused("product-not-found"),
        Err(error)
            if error
                .status()
                .is_some_and(|status| status == 408 || status >= 500) =>
        {
            retryable("transport-unavailable")
        }
        Err(BaseRegistryClientError::InvalidRequest { .. }) => refused("invalid-command"),
        Err(BaseRegistryClientError::Protocol { .. }) => refused("invalid-response"),
        Err(_) => refused("product-refused"),
    }
}

#[async_trait]
impl AdapterSet for HttpAdapters {
    fn binding_digest(&self) -> &str {
        &self.digest
    }

    fn binding_digest_for(&self, workflow: &crate::definition::Workflow) -> String {
        self.config
            .binding_digest_for(workflow)
            .unwrap_or_else(|_| "invalid-workflow-binding".into())
    }

    async fn prepare(
        &self,
        request: &CallRequest,
    ) -> std::result::Result<Option<Vec<u8>>, CallOutcome> {
        if request.operation == Operation::InvokeBregAction {
            return match self.connections.get(&request.connection) {
                Some(Connection::Breg {
                    client, profile, ..
                }) => crate::breg_action::prepare(client, profile, request)
                    .await
                    .map(Some),
                _ => Err(refused("operation-unbound")),
            };
        }
        Ok(None)
    }

    async fn call_prepared(&self, request: &CallRequest, prepared: Option<&[u8]>) -> CallOutcome {
        if request.operation == Operation::InvokeBregAction {
            return match (self.connections.get(&request.connection), prepared) {
                (
                    Some(Connection::Breg {
                        client, profile, ..
                    }),
                    Some(bytes),
                ) => crate::breg_action::execute(client, profile, request, bytes).await,
                _ => refused("operation-unbound"),
            };
        }
        if prepared.is_some() {
            return refused("invalid-command");
        }
        self.call(request).await
    }

    async fn call(&self, request: &CallRequest) -> CallOutcome {
        match (self.connections.get(&request.connection), request.operation) {
            (Some(Connection::External(connection)), Operation::ExternalGet) => {
                connection.get(&request.input).await
            }
            (
                Some(Connection::Breg {
                    client, options, ..
                }),
                Operation::ReadRecord,
            ) => {
                let input: ReadRequest = match serde_json::from_value(request.input.clone()) {
                    Ok(input) => input,
                    Err(_) => return refused("invalid-command"),
                };
                if input.grant.is_some() {
                    return refused("invalid-command");
                }
                read_record(client, options, &input).await
            }
            (Some(Connection::BregTask(connection)), Operation::ReadRecord) => {
                let input: ReadRequest = match serde_json::from_value(request.input.clone()) {
                    Ok(input) => input,
                    Err(_) => return refused("invalid-command"),
                };
                let Some(grant) = &input.grant else {
                    return refused("invalid-command");
                };
                let client = match connection.client(grant) {
                    Ok(client) => client,
                    Err(outcome) => return outcome,
                };
                read_record(&client, &connection.options, &input).await
            }
            (Some(Connection::Scheduling(connection)), operation)
                if operation.product() == "scheduling" =>
            {
                scheduling_call(
                    &connection.client,
                    &connection.authorization,
                    &connection.key,
                    connection.standing.as_deref(),
                    request,
                )
                .await
            }
            (Some(Connection::Messaging { client, tokens }), Operation::SubmitMessage) => {
                let Some(key) = &request.idempotency_key else {
                    return refused("invalid-command");
                };
                let input: SubmitMessageRequest =
                    match serde_json::from_value(request.input.clone()) {
                        Ok(input) => input,
                        Err(_) => return refused("invalid-command"),
                    };
                if key.is_empty()
                    || key.len() > 128
                    || !key.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
                    || input.template.as_ref().is_some_and(|template| {
                        !registry_messaging_core::valid_identifier(&template.id)
                            || !registry_messaging_core::valid_template_version(&template.version)
                    })
                {
                    return refused("invalid-command");
                }
                let token = match tokens.bearer_token().await {
                    Ok(token) => token,
                    Err(error) => return token_failure(&error),
                };
                match client.submit(&token, key, &input).await {
                    Ok(answer) => match serde_json::to_value(answer.value) {
                        Ok(value) => CallOutcome::Success(value),
                        Err(_) => CallOutcome::Uncertain {
                            code: "invalid-response".to_owned(),
                        },
                    },
                    Err(MessagingClientError::Problem {
                        code: ProblemCode::IdempotencyExpired,
                        ..
                    }) => CallOutcome::ReceiptExpired,
                    Err(error) if error.is_outcome_unknown() => CallOutcome::Uncertain {
                        code: "transport-uncertain".to_owned(),
                    },
                    Err(MessagingClientError::Transport { .. }) => {
                        retryable("transport-unavailable")
                    }
                    Err(MessagingClientError::Problem { status: 429, .. }) => {
                        retryable("rate-limited")
                    }
                    Err(MessagingClientError::Problem {
                        status: 401 | 403, ..
                    }) => refused("product-forbidden"),
                    Err(MessagingClientError::Problem {
                        code: ProblemCode::TemplateNotFound | ProblemCode::TemplateLocaleUnavailable,
                        ..
                    }) => refused("product-not-found"),
                    Err(MessagingClientError::InvalidRequest { .. }) => refused("invalid-command"),
                    Err(_) => refused("product-refused"),
                }
            }
            _ => refused("operation-unbound"),
        }
    }

    async fn reconcile(
        &self,
        request: &CallRequest,
        _accepted: Option<&serde_json::Value>,
    ) -> ReconciliationOutcome {
        let Some(idempotency_key) = request
            .idempotency_key
            .as_deref()
            .filter(|key| valid_key(key))
        else {
            return unresolved("invalid-command");
        };
        match (self.connections.get(&request.connection), request.operation) {
            (Some(Connection::Messaging { client, tokens }), Operation::SubmitMessage) => {
                let input: SubmitMessageRequest =
                    match serde_json::from_value(request.input.clone()) {
                        Ok(input) => input,
                        Err(_) => return unresolved("invalid-command"),
                    };
                let token = match tokens.bearer_token().await {
                    Ok(token) => token,
                    Err(_) => return unresolved("observation-unavailable"),
                };
                match client
                    .message_receipt(&token, idempotency_key, &input)
                    .await
                {
                    Ok(answer) => match serde_json::to_value(answer.value) {
                        Ok(value) => ReconciliationOutcome::Confirmed(value),
                        Err(_) => unresolved("invalid-observation"),
                    },
                    Err(MessagingClientError::Problem {
                        code: ProblemCode::IdempotencyExpired | ProblemCode::ReceiptUnresolved,
                        ..
                    }) => unresolved("receipt-unresolved"),
                    Err(_) => unresolved("observation-unavailable"),
                }
            }
            (Some(Connection::Scheduling(connection)), Operation::CreateAppointment) => {
                let SchedulingConnection {
                    client,
                    authorization,
                    observation,
                    ..
                } = connection.as_ref();
                let input: AppointmentRequest = match serde_json::from_value(request.input.clone())
                {
                    Ok(input) => input,
                    Err(_) => return unresolved("invalid-command"),
                };
                if authorization.task_authority.is_none()
                    || input.appointment.hold.is_some()
                    || input.appointment.admission.is_none()
                {
                    return unresolved("invalid-command");
                }
                // This separately configured read identity can observe only its
                // original issuer/subject receipt. It is never used by dispatch.
                let Some(observation) = observation else {
                    return unresolved("observation-unavailable");
                };
                let token = match observation.bearer_token().await {
                    Ok(token) => token,
                    Err(_) => return unresolved("observation-unavailable"),
                };
                match client
                    .appointment_receipt(
                        SchedulingAuth::new(&token),
                        idempotency_key,
                        &input.appointment,
                    )
                    .await
                {
                    Ok(answer) => match serde_json::to_value(answer.value) {
                        Ok(value) => ReconciliationOutcome::Confirmed(value),
                        Err(_) => unresolved("invalid-observation"),
                    },
                    Err(SchedulingClientError::Problem {
                        code:
                            SchedulingProblemCode::IdempotencyExpired
                            | SchedulingProblemCode::ReceiptUnresolved,
                        ..
                    }) => unresolved("receipt-unresolved"),
                    Err(_) => unresolved("observation-unavailable"),
                }
            }
            _ => unresolved("operation-unbound"),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SchedulingReadRequest {
    #[serde(default)]
    grant: Option<GrantReference>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AvailabilityRequest {
    offering: String,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    limit: u32,
    #[serde(default)]
    grant: Option<GrantReference>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AppointmentRequest {
    grant: GrantReference,
    appointment: CreateAppointmentRequest,
}

async fn scheduling_token(
    auth: &AuthorizationConfig,
    key: &PrivateJwk,
    standing: Option<&PrivateKeyJwt>,
    grant: Option<&GrantReference>,
) -> std::result::Result<registry_platform_httputil::client::BearerToken, CallOutcome> {
    if auth.task_authority.is_some() {
        let grant = grant.ok_or_else(|| refused("invalid-command"))?;
        task_provider(auth, key, grant)?
            .bearer_token()
            .await
            .map_err(|error| token_failure(&error))
    } else {
        if grant.is_some() {
            return Err(refused("invalid-command"));
        }
        standing
            .ok_or_else(|| refused("credential-configuration"))?
            .bearer_token()
            .await
            .map_err(|error| token_failure(&error))
    }
}

fn scheduling_failure(error: SchedulingClientError, mutation: bool) -> CallOutcome {
    if mutation
        && matches!(
            &error,
            SchedulingClientError::Problem {
                code: SchedulingProblemCode::IdempotencyExpired,
                ..
            }
        )
    {
        return CallOutcome::ReceiptExpired;
    }
    if mutation && error.is_outcome_unknown() {
        return CallOutcome::Uncertain {
            code: "transport-uncertain".into(),
        };
    }
    match error {
        SchedulingClientError::Transport { .. } => retryable("transport-unavailable"),
        SchedulingClientError::Problem { status: 429, .. }
        | SchedulingClientError::Protocol { status: 429, .. } => retryable("rate-limited"),
        SchedulingClientError::Problem {
            status: 401 | 403, ..
        } => refused("product-forbidden"),
        SchedulingClientError::Problem { status: 404, .. } => refused("product-not-found"),
        SchedulingClientError::Problem {
            status: 408 | 500..=599,
            ..
        }
        | SchedulingClientError::Protocol {
            status: 408 | 500..=599,
            ..
        } => retryable("transport-unavailable"),
        SchedulingClientError::InvalidRequest { .. } => refused("invalid-command"),
        SchedulingClientError::Protocol { .. } => refused("invalid-response"),
        _ => refused("product-refused"),
    }
}

fn scheduling_success<T: serde::Serialize>(value: T, mutation: bool) -> CallOutcome {
    match serde_json::to_value(value) {
        Ok(value) => CallOutcome::Success(value),
        Err(_) if mutation => CallOutcome::Uncertain {
            code: "invalid-response".into(),
        },
        Err(_) => refused("invalid-response"),
    }
}

async fn scheduling_call(
    client: &SchedulingClient,
    auth: &AuthorizationConfig,
    key: &PrivateJwk,
    standing: Option<&PrivateKeyJwt>,
    request: &CallRequest,
) -> CallOutcome {
    match request.operation {
        Operation::ReadScheduling => {
            let input: SchedulingReadRequest = match serde_json::from_value(request.input.clone()) {
                Ok(input) => input,
                Err(_) => return refused("invalid-command"),
            };
            let token = match scheduling_token(auth, key, standing, input.grant.as_ref()).await {
                Ok(token) => token,
                Err(outcome) => return outcome,
            };
            match client.get_scheduling(SchedulingAuth::new(&token)).await {
                Ok(answer) => scheduling_success(answer.value, false),
                Err(error) => scheduling_failure(error, false),
            }
        }
        Operation::ReadAvailability => {
            let input: AvailabilityRequest = match serde_json::from_value(request.input.clone()) {
                Ok(input) => input,
                Err(_) => return refused("invalid-command"),
            };
            // The finite workflow receives one bounded interval and one page.
            if input.start >= input.end
                || input.end - input.start > chrono::Duration::days(31)
                || !(1..=100).contains(&input.limit)
            {
                return refused("invalid-command");
            }
            let token = match scheduling_token(auth, key, standing, input.grant.as_ref()).await {
                Ok(token) => token,
                Err(outcome) => return outcome,
            };
            match client
                .availability(
                    SchedulingAuth::new(&token),
                    &input.offering,
                    Some(input.start),
                    Some(input.end),
                    None,
                    Some(input.limit),
                )
                .await
            {
                Ok(answer) => scheduling_success(answer.value, false),
                Err(error) => scheduling_failure(error, false),
            }
        }
        Operation::CreateAppointment => {
            let input: AppointmentRequest = match serde_json::from_value(request.input.clone()) {
                Ok(input) => input,
                Err(_) => return refused("invalid-command"),
            };
            let Some(idempotency_key) = request.idempotency_key.as_deref() else {
                return refused("invalid-command");
            };
            if auth.task_authority.is_none()
                || !valid_key(idempotency_key)
                || input.appointment.hold.is_some()
                || input.appointment.admission.is_none()
            {
                return refused("invalid-command");
            }
            let token = match scheduling_token(auth, key, None, Some(&input.grant)).await {
                Ok(token) => token,
                Err(outcome) => return outcome,
            };
            match client
                .create_appointment(
                    SchedulingAuth::new(&token),
                    idempotency_key,
                    &input.appointment,
                )
                .await
            {
                Ok(answer) => scheduling_success(answer.value, true),
                Err(error) => scheduling_failure(error, true),
            }
        }
        _ => refused("operation-unbound"),
    }
}

fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 128 && key.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn unresolved(code: &str) -> ReconciliationOutcome {
    ReconciliationOutcome::Unresolved { code: code.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_https_peers_allow_private_networks_and_metadata_and_cleartext_stay_denied() {
        let https: Url = "https://10.0.0.8/token".parse().unwrap();
        assert!(configured_endpoint_policy(&https)
            .validate_dns_pinned_for_immediate_fetch(&https)
            .is_ok());
        let metadata: Url = "https://169.254.169.254/token".parse().unwrap();
        assert!(configured_endpoint_policy(&metadata)
            .validate_dns_pinned_for_immediate_fetch(&metadata)
            .is_err());
        let cleartext: Url = "http://10.0.0.8/token".parse().unwrap();
        assert!(configured_endpoint_policy(&cleartext)
            .validate_dns_pinned_for_immediate_fetch(&cleartext)
            .is_err());
    }
}
