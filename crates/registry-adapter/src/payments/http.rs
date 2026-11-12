// SPDX-License-Identifier: Apache-2.0
//! Typed payment routes sharing the Adapter's authentication and database host.

use super::{
    config::{PaymentsConfig, API_VERSION, KIND},
    g2p_config::G2pConnection,
    g2p_model::{G2pAttempt, G2pAttemptState, G2pError},
    g2p_registry::BregG2pBridge,
    g2p_service::{G2pService, HttpG2pProvider},
    g2p_store::{migrate_g2p, G2pStore},
    pack::{
        ConnectorKind, PaymentCapability, PaymentOperationMapping, PaymentProviderAuth,
        PaymentProviderPack, ProviderPackPin,
    },
    provider_mapping::{PaymentMappingProgram, PaymentMappingRegistry},
    registry::BregBridge,
    service::{PaymentService, SyntheticProvider},
    store::{migrate, PaymentStore},
};
use crate::serve::{Authenticator, Caller, CallerRefusal, ServeError};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path as RoutePath, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use registry_adapter_core::AdapterRuntimeConfig;
use registry_payment_protocol::{
    DisbursementAccepted, DisbursementState, DisbursementStatus, Money, PaymentProblem,
    PaymentProblemCode as Error, ProviderConfirmation, RecordProviderConfirmation, RecordReceipt,
    RequestCollection, RequestDisbursement,
};
use registry_platform_config::{
    RuntimeConfigLoader, RuntimeEnvelope, SecretProvider, SecretResolver,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

struct HttpState {
    authenticator: Authenticator,
    service: PaymentService,
    g2p: G2pService,
    disbursements: Vec<G2pConnection>,
}

/// Fixed payment routes and wire schemas, without origins or credential references.
#[cfg(feature = "schema")]
pub fn contract(config: &PaymentsConfig) -> serde_json::Value {
    use registry_payment_protocol::ReadDisbursement;
    use registry_payment_protocol::{CollectionAccepted, CollectionStatus, RegistryReceipt};
    serde_json::json!({
        "protocol":"payments/v1",
        "authentication":"OIDC access tokens under the Adapter runtime issuer and client policy",
        "simulation":config.disbursements.is_empty() && config.connections.iter().all(|connection| connection.binding.simulation),
        "connections":config.connections.iter().map(|connection| {
            let base=format!("/v1/payments/{}/collections",connection.id);
            serde_json::json!({
                "connection":connection.id,
                "allowedClients":connection.allowed_clients,
                "requiredScope":connection.required_scope,
                "operations":[
                    {"operation":"payments.request-collection/v1","method":"POST","path":base,"successStatus":202,"effect":"mutation"},
                    {"operation":"payments.request-collection-receipt/v1","method":"POST","path":format!("{base}/receipt"),"successStatus":200,"effect":"read","recoveryOnly":true},
                    {"operation":"payments.read-collection/v1","method":"GET","path":format!("{base}/{{collectionId}}"),"successStatus":200,"effect":"read"},
                    {"operation":"payments.record-receipt/v1","method":"POST","path":format!("{base}/{{collectionId}}/record-receipt"),"successStatus":200,"effect":"mutation"}
                ]
            })
        }).chain(config.disbursements.iter().map(|connection| {
            let base=format!("/v1/payments/{}/disbursements",connection.id);
            serde_json::json!({
                "connection":connection.id,
                "allowedClients":connection.allowed_clients,
                "requiredScope":connection.required_scope,
                "operations":[
                    {"operation":"payments.request-disbursement/v1","method":"POST","path":base,"successStatus":202,"effect":"mutation"},
                    {"operation":"payments.request-disbursement-receipt/v1","method":"POST","path":format!("{base}/receipt"),"successStatus":200,"effect":"read","recoveryOnly":true},
                    {"operation":"payments.read-disbursement/v1","method":"GET","path":format!("{base}/{{disbursementId}}"),"successStatus":200,"effect":"read"},
                    {"operation":"payments.record-provider-confirmation/v1","method":"POST","path":format!("{base}/{{disbursementId}}/record-provider-confirmation"),"successStatus":200,"effect":"mutation"}
                ]
            })
        })).collect::<Vec<_>>(),
        "schemas":{
            "RequestCollection":schemars::schema_for!(RequestCollection),
            "CollectionAccepted":schemars::schema_for!(CollectionAccepted),
            "CollectionStatus":schemars::schema_for!(CollectionStatus),
            "RecordReceipt":schemars::schema_for!(RecordReceipt),
            "RegistryReceipt":schemars::schema_for!(RegistryReceipt),
            "RequestDisbursement":schemars::schema_for!(RequestDisbursement),
            "ReadDisbursement":schemars::schema_for!(ReadDisbursement),
            "DisbursementAccepted":schemars::schema_for!(DisbursementAccepted),
            "DisbursementStatus":schemars::schema_for!(DisbursementStatus),
            "RecordProviderConfirmation":schemars::schema_for!(RecordProviderConfirmation),
            "ProviderConfirmation":schemars::schema_for!(ProviderConfirmation),
            "PaymentProblem":schemars::schema_for!(PaymentProblem)
        }
    })
}

pub fn load_config(path: &Path) -> Result<PaymentsConfig, ServeError> {
    let absolute = std::fs::canonicalize(path)
        .map_err(|_| refused("payment configuration could not be read"))?;
    let config = RuntimeConfigLoader::new(RuntimeEnvelope {
        api_version: API_VERSION,
        kind: KIND,
    })
    .load::<PaymentsConfig>(&absolute)
    .map_err(|_| refused("payment configuration was refused"))?
    .config;
    config
        .validate()
        .map_err(|_| refused("payment connections were refused"))?;
    Ok(config)
}

fn resolver(runtime: &AdapterRuntimeConfig) -> Result<SecretResolver, ServeError> {
    match &runtime.secret_providers {
        Some(providers) => providers.resolver(),
        None => SecretResolver::new([SecretProvider::Environment], ""),
    }
    .map_err(|_| refused("payment secret providers were refused"))
}

fn mapping_auth_matches(
    operation: Option<&PaymentOperationMapping>,
    expected: PaymentProviderAuth,
) -> bool {
    operation.is_some_and(|operation| operation.auth == expected)
}

fn live_disbursement_auth_supported(auth: PaymentProviderAuth) -> bool {
    matches!(
        auth,
        PaymentProviderAuth::Bearer | PaymentProviderAuth::MifosLegacySignature
    )
}

const MAX_PAYMENT_PROVIDER_PACKS: usize = 32;

struct LoadedPaymentPacks {
    by_digest: BTreeMap<String, (PaymentProviderPack, Vec<u8>)>,
    mapping: Option<Arc<PaymentMappingRegistry>>,
}

impl LoadedPaymentPacks {
    fn for_pin(&self, pin: &ProviderPackPin) -> Result<&PaymentProviderPack, ServeError> {
        let (pack, bytes) = self
            .by_digest
            .get(&pin.digest)
            .ok_or_else(|| refused("pinned payment provider pack was not supplied"))?;
        pack.check_pin(pin, bytes)
            .map_err(|_| refused("payment provider pack pin differs"))?;
        Ok(pack)
    }
}

fn load_provider_packs(paths: &[PathBuf]) -> Result<LoadedPaymentPacks, ServeError> {
    if paths.len() > MAX_PAYMENT_PROVIDER_PACKS {
        return Err(refused("too many payment provider packs were supplied"));
    }
    let mut by_digest = BTreeMap::new();
    let mut mapping = PaymentMappingRegistry::new();
    let mut mapped_count = 0;
    for path in paths {
        let absolute = std::fs::canonicalize(path)
            .map_err(|_| refused("payment provider pack could not be read"))?;
        let bytes = std::fs::read(&absolute)
            .map_err(|_| refused("payment provider pack could not be read"))?;
        let pack = PaymentProviderPack::from_yaml(&bytes)
            .map_err(|_| refused("payment provider pack was refused"))?;
        pack.validate()
            .map_err(|_| refused("payment provider pack was refused"))?;
        let digest = registry_platform_config::sha256_uri(&bytes);
        if by_digest.contains_key(&digest) {
            return Err(refused("payment provider pack was supplied more than once"));
        }
        if pack.connector == ConnectorKind::AdapterPaymentHttpV1 {
            let root = absolute
                .parent()
                .ok_or_else(|| refused("payment provider pack path was refused"))?;
            let scripts = pack
                .mapping
                .as_ref()
                .ok_or_else(|| refused("payment provider pack mapping was refused"))?
                .scripts
                .iter()
                .map(|script| {
                    let script_path =
                        std::fs::canonicalize(root.join(&script.path)).map_err(|_| {
                            refused("payment provider mapping artifact could not be read")
                        })?;
                    if !script_path.starts_with(root) || !script_path.is_file() {
                        return Err(refused("payment provider mapping artifact was refused"));
                    }
                    let bytes = std::fs::read(script_path).map_err(|_| {
                        refused("payment provider mapping artifact could not be read")
                    })?;
                    Ok((script.path.clone(), bytes))
                })
                .collect::<Result<BTreeMap<_, _>, ServeError>>()?;
            let program = PaymentMappingProgram::compile(&pack, &bytes, &scripts)
                .map_err(|_| refused("payment provider mapping was refused"))?;
            mapping
                .insert(program)
                .map_err(|_| refused("payment provider mapping registry was refused"))?;
            mapped_count += 1;
        }
        by_digest.insert(digest, (pack, bytes));
    }
    Ok(LoadedPaymentPacks {
        by_digest,
        mapping: (mapped_count > 0).then(|| Arc::new(mapping)),
    })
}

pub async fn load_router(
    runtime: &AdapterRuntimeConfig,
    path: &Path,
    provider_pack_paths: &[PathBuf],
    pool: deadpool_postgres::Pool,
) -> Result<Router, ServeError> {
    let config = load_config(path)?;
    let packs = load_provider_packs(provider_pack_paths)?;
    for connection in &config.connections {
        let Some(pin) = connection.binding.provider_pack.as_ref() else {
            if connection.binding.simulation {
                continue;
            }
            return Err(refused("payment connection must pin the provider pack"));
        };
        let pack = packs.for_pin(pin)?;
        if pack.connector != connection.binding.connector_kind()
            || !pack.capabilities.contains(&PaymentCapability::Collection)
        {
            return Err(refused(
                "payment provider pack lacks collection capability or connector",
            ));
        }
        if matches!(
            &connection.binding.provider,
            super::config::CollectionProvider::Http { .. }
        ) && !mapping_auth_matches(
            pack.mapping
                .as_ref()
                .and_then(|mapping| mapping.collection.as_ref()),
            PaymentProviderAuth::Bearer,
        ) {
            return Err(refused(
                "payment provider collection mapping requires unsupported authentication",
            ));
        }
    }
    for connection in &config.disbursements {
        let pack = packs.for_pin(&connection.binding.provider_pack)?;
        if pack.connector != ConnectorKind::AdapterPaymentHttpV1
            || !pack.capabilities.contains(&PaymentCapability::Disbursement)
        {
            return Err(refused(
                "payment provider pack lacks generic HTTP disbursement capability",
            ));
        }
        if !mapping_auth_matches(
            pack.mapping
                .as_ref()
                .and_then(|mapping| mapping.disbursement.as_ref()),
            connection.binding.provider.auth_profile(),
        ) {
            return Err(refused(
                "payment provider disbursement mapping authentication differs from the connection",
            ));
        }
        if !live_disbursement_auth_supported(connection.binding.provider.auth_profile()) {
            return Err(refused(
                "payment provider disbursement authentication is not implemented by the live host",
            ));
        }
    }
    let resolver = Arc::new(resolver(runtime)?);
    for connection in &config.connections {
        for reference in [
            &connection.binding.provider_credential_ref,
            &connection.binding.registry.credential_ref,
        ] {
            let value = resolver
                .resolve(reference.as_str())
                .map_err(|_| refused("a payment credential could not be resolved"))?;
            let value = std::str::from_utf8(value.expose_secret())
                .map_err(|_| refused("a payment credential was refused"))?;
            registry_platform_httputil::client::BearerToken::new(value.to_owned())
                .map_err(|_| refused("a payment credential was refused"))?;
        }
    }
    for connection in &config.disbursements {
        let references = [
            connection.binding.provider.credential_ref(),
            &connection.binding.registry.credential_ref,
        ];
        for reference in references {
            let value = resolver
                .resolve(reference.as_str())
                .map_err(|_| refused("a payment credential could not be resolved"))?;
            let value = std::str::from_utf8(value.expose_secret())
                .map_err(|_| refused("a payment credential was refused"))?;
            registry_platform_httputil::client::BearerToken::new(value.to_owned())
                .map_err(|_| refused("a payment credential was refused"))?;
        }
    }
    let authenticator = crate::serve::authenticator(runtime, &resolver).await?;
    let migration = crate::serve::pool(&runtime.database, &resolver, true)?;
    {
        let mut client = migration
            .get()
            .await
            .map_err(|_| refused("payment migration database unavailable"))?;
        migrate(&mut client)
            .await
            .map_err(|_| refused("payment database migration failed"))?;
        migrate_g2p(&mut client)
            .await
            .map_err(|_| refused("G2P database migration failed"))?;
    }
    let store = PaymentStore::new(pool.clone(), runtime.id.as_str().to_owned());
    store
        .check_privileges()
        .await
        .map_err(|_| refused("payment runtime role lacks required table or sequence privileges"))?;
    let g2p_store = G2pStore::new(pool.clone(), runtime.id.as_str().to_owned());
    if !config.disbursements.is_empty() {
        g2p_store
            .check_privileges()
            .await
            .map_err(|_| refused("G2P runtime role lacks required table or sequence privileges"))?;
    }
    let g2p_provider_bindings = config
        .disbursements
        .iter()
        .map(|connection| connection.binding.provider.clone())
        .collect::<Vec<_>>();
    let g2p_provider = HttpG2pProvider::initialize(resolver.clone(), &g2p_provider_bindings)
        .await
        .map_err(|_| refused("payment disbursement authentication initialization failed"))?;
    let g2p = G2pService::new(
        g2p_store,
        Arc::new(BregG2pBridge::new(resolver.clone())),
        Arc::new(g2p_provider),
    );
    let g2p = if let Some(mapping) = packs.mapping.clone() {
        g2p.with_mapping(mapping)
    } else {
        g2p
    };
    let disbursements = config.disbursements.clone();
    let service = PaymentService::new(
        config,
        store,
        Arc::new(BregBridge::new(resolver.clone())),
        Arc::new(SyntheticProvider::new(resolver, packs.mapping)),
    )
    .map_err(|_| refused("payment service was refused"))?;
    let state = Arc::new(HttpState {
        authenticator,
        service,
        g2p,
        disbursements,
    });
    Ok(Router::new()
        .route("/v1/payments/{connection}/collections", post(request))
        .route(
            "/v1/payments/{connection}/collections/receipt",
            post(request_receipt),
        )
        .route(
            "/v1/payments/{connection}/collections/{collection}",
            get(read),
        )
        .route(
            "/v1/payments/{connection}/collections/{collection}/record-receipt",
            post(record_receipt),
        )
        .route(
            "/v1/payments/{connection}/disbursements",
            post(request_disbursement),
        )
        .route(
            "/v1/payments/{connection}/disbursements/receipt",
            post(disbursement_receipt),
        )
        .route(
            "/v1/payments/{connection}/disbursements/{disbursement}",
            get(read_disbursement),
        )
        .route(
            "/v1/payments/{connection}/disbursements/{disbursement}/record-provider-confirmation",
            post(record_provider_confirmation),
        )
        .layer(DefaultBodyLimit::max(4096))
        .with_state(state))
}

pub async fn run_only(
    runtime_path: &Path,
    payments_path: &Path,
    provider_pack_paths: &[PathBuf],
) -> Result<(), ServeError> {
    let absolute = std::fs::canonicalize(runtime_path)
        .map_err(|_| refused("runtime configuration could not be read"))?;
    let runtime = RuntimeConfigLoader::new(RuntimeEnvelope {
        api_version: registry_adapter_core::ADAPTER_RUNTIME_API_VERSION,
        kind: registry_adapter_core::ADAPTER_RUNTIME_KIND,
    })
    .removed_keys(registry_adapter_core::ADAPTER_REMOVED_KEYS)
    .load::<AdapterRuntimeConfig>(&absolute)
    .map_err(|_| refused("runtime configuration was refused"))?
    .config;
    let resolver = resolver(&runtime)?;
    let pool = crate::serve::pool(&runtime.database, &resolver, false)?;
    let router = load_router(&runtime, payments_path, provider_pack_paths, pool).await?;
    let shutdown = crate::serve::shutdown_signal()?;
    let listener = tokio::net::TcpListener::bind(runtime.listener.bind.0)
        .await
        .map_err(|_| refused("payment listener could not bind"))?;
    tracing::info!("payment listener ready");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|_| refused("payment listener stopped"))
}

async fn caller(state: &HttpState, headers: &HeaderMap) -> Result<Caller, HttpError> {
    let value =
        single_header(headers, "authorization").map_err(|_| HttpError(Error::Unauthenticated))?;
    let bearer = value
        .strip_prefix("Bearer ")
        .ok_or(HttpError(Error::Unauthenticated))?;
    state
        .authenticator
        .authenticate(bearer)
        .await
        .map_err(|error| {
            HttpError(match error {
                CallerRefusal::Unauthenticated => Error::Unauthenticated,
                CallerRefusal::Unavailable => Error::Unavailable,
            })
        })
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, HttpError> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().map_err(|_| HttpError(Error::InvalidRequest)),
        _ => Err(HttpError(Error::InvalidRequest)),
    }
}
fn body<T: DeserializeOwned>(headers: &HeaderMap, uri: &Uri, body: &[u8]) -> Result<T, HttpError> {
    if uri.query().is_some() || single_header(headers, "content-type")? != "application/json" {
        return Err(HttpError(Error::InvalidRequest));
    }
    serde_json::from_slice(body).map_err(|_| HttpError(Error::InvalidRequest))
}
fn collection(value: &str) -> Result<Uuid, HttpError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or(HttpError(Error::InvalidRequest))
}

async fn request(
    State(state): State<Arc<HttpState>>,
    RoutePath(connection): RoutePath<String>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, HttpError> {
    let caller = caller(&state, &headers).await?;
    let request: RequestCollection = body(&headers, &uri, &bytes)?;
    let key = single_header(&headers, "idempotency-key")?;
    let result = state
        .service
        .request(&connection, &caller, key, &request)
        .await;
    finish(
        &state,
        &caller,
        "request",
        None,
        true,
        StatusCode::ACCEPTED,
        result,
    )
    .await
}
async fn request_receipt(
    State(state): State<Arc<HttpState>>,
    RoutePath(connection): RoutePath<String>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, HttpError> {
    let caller = caller(&state, &headers).await?;
    let request: RequestCollection = body(&headers, &uri, &bytes)?;
    let key = single_header(&headers, "idempotency-key")?;
    let result = state
        .service
        .request_receipt(&connection, &caller, key, &request)
        .await;
    finish(
        &state,
        &caller,
        "request-receipt",
        None,
        false,
        StatusCode::OK,
        result,
    )
    .await
}
async fn read(
    State(state): State<Arc<HttpState>>,
    RoutePath((connection, id)): RoutePath<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, HttpError> {
    let caller = caller(&state, &headers).await?;
    if uri.query().is_some() || !bytes.is_empty() {
        return Err(HttpError(Error::InvalidRequest));
    }
    let id = collection(&id)?;
    let result = state.service.read(&connection, &caller, id).await;
    finish(
        &state,
        &caller,
        "read",
        Some(id),
        false,
        StatusCode::OK,
        result,
    )
    .await
}
async fn record_receipt(
    State(state): State<Arc<HttpState>>,
    RoutePath((connection, id)): RoutePath<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, HttpError> {
    let caller = caller(&state, &headers).await?;
    let id = collection(&id)?;
    let request: RecordReceipt = body(&headers, &uri, &bytes)?;
    if request.collection_id != id {
        return Err(HttpError(Error::InvalidRequest));
    }
    let key = single_header(&headers, "idempotency-key")?;
    let result = state
        .service
        .record_receipt(&connection, &caller, key, id)
        .await;
    finish(
        &state,
        &caller,
        "record-receipt",
        Some(id),
        true,
        StatusCode::OK,
        result,
    )
    .await
}

async fn g2p_connection<'a>(
    state: &'a HttpState,
    id: &str,
    caller: &Caller,
    operation: &str,
) -> Result<&'a G2pConnection, HttpError> {
    let selected = state
        .disbursements
        .iter()
        .find(|entry| entry.id == id)
        .ok_or(Error::NotFound)
        .and_then(|connection| {
            if !connection.allowed_clients.contains(&caller.client_id)
                || !caller.scopes.contains(&connection.required_scope)
            {
                Err(Error::Forbidden)
            } else {
                Ok(connection)
            }
        });
    if let Err(error) = selected {
        state
            .service
            .audit_access(caller, operation, None, Some(error))
            .await
            .map_err(|_| HttpError(Error::Unavailable))?;
    }
    selected.map_err(HttpError)
}

fn g2p_principal(caller: &Caller) -> Result<String, Error> {
    super::model::digest(&[&caller.issuer, &caller.client_id, &caller.reference])
}

fn g2p_error(error: G2pError) -> Error {
    match error {
        G2pError::InvalidRequest => Error::InvalidRequest,
        G2pError::Conflict => Error::Conflict,
        G2pError::NotFound => Error::NotFound,
        G2pError::Unavailable => Error::Unavailable,
        G2pError::OutcomeUnknown => Error::OutcomeUnknown,
        G2pError::RecoveryHeld => Error::RecoveryHeld,
    }
}

fn disbursement_accepted(attempt: &G2pAttempt) -> Result<DisbursementAccepted, Error> {
    if attempt.provider_acceptance.is_none() {
        return Err(Error::OutcomeUnknown);
    }
    let accepted = DisbursementAccepted {
        disbursement_id: attempt.id,
        instruction_record_id: attempt.instruction.record_id,
        instruction_id: attempt.instruction.instruction_id,
        instruction_version: attempt.instruction.instruction_version,
        binding_revision: attempt.binding_revision.clone(),
        simulation: false,
    };
    accepted.validate().map_err(|_| Error::Unavailable)?;
    Ok(accepted)
}

fn disbursement_status(attempt: &G2pAttempt) -> Result<DisbursementStatus, Error> {
    let state = match attempt.state {
        G2pAttemptState::ProviderAccepted => DisbursementState::Accepted,
        G2pAttemptState::ProviderPending => DisbursementState::Pending,
        G2pAttemptState::ProviderConfirmed
        | G2pAttemptState::ConfirmationPrepared
        | G2pAttemptState::ConfirmationRecorded => DisbursementState::ProviderConfirmed,
        G2pAttemptState::ProviderFailed => DisbursementState::Failed,
        G2pAttemptState::BindPrepared
        | G2pAttemptState::Bound
        | G2pAttemptState::DispatchStarted
        | G2pAttemptState::ProviderUnknown => DisbursementState::Unknown,
    };
    let value = DisbursementStatus {
        disbursement_id: attempt.id,
        instruction_record_id: attempt.instruction.record_id,
        instruction_id: attempt.instruction.instruction_id,
        instruction_version: attempt.instruction.instruction_version,
        binding_revision: attempt.binding_revision.clone(),
        simulation: false,
        state,
        money: Money {
            value: attempt.instruction.amount(),
            currency: attempt.instruction.currency.clone(),
            scale: attempt.instruction.currency_scale,
        },
        provider_reference: if state == DisbursementState::ProviderConfirmed {
            attempt
                .provider_observation
                .as_ref()
                .and_then(|observation| observation.provider_reference.clone())
        } else {
            None
        },
        failure_reason: (state == DisbursementState::Failed)
            .then(|| "provider-reported-failure".to_owned()),
    };
    value.validate().map_err(|_| Error::Unavailable)?;
    Ok(value)
}

async fn request_disbursement(
    State(state): State<Arc<HttpState>>,
    RoutePath(connection): RoutePath<String>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, HttpError> {
    let caller = caller(&state, &headers).await?;
    let request: RequestDisbursement = body(&headers, &uri, &bytes)?;
    request
        .validate()
        .map_err(|_| HttpError(Error::InvalidRequest))?;
    let key = single_header(&headers, "idempotency-key")?;
    if !super::config::text(key, 128) {
        return Err(HttpError(Error::InvalidRequest));
    }
    let selected = g2p_connection(&state, &connection, &caller, "request-disbursement").await?;
    let result = state
        .g2p
        .request_disbursement(
            &connection,
            &g2p_principal(&caller).map_err(HttpError)?,
            key,
            request.instruction_record_id,
            request.instruction_version,
            selected.binding.clone(),
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .await
        .map_err(g2p_error)
        .and_then(|attempt| disbursement_accepted(&attempt));
    finish(
        &state,
        &caller,
        "request-disbursement",
        None,
        true,
        StatusCode::ACCEPTED,
        result,
    )
    .await
}

async fn disbursement_receipt(
    State(state): State<Arc<HttpState>>,
    RoutePath(connection): RoutePath<String>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, HttpError> {
    let caller = caller(&state, &headers).await?;
    let request: RequestDisbursement = body(&headers, &uri, &bytes)?;
    request
        .validate()
        .map_err(|_| HttpError(Error::InvalidRequest))?;
    let key = single_header(&headers, "idempotency-key")?;
    if !super::config::text(key, 128) {
        return Err(HttpError(Error::InvalidRequest));
    }
    g2p_connection(&state, &connection, &caller, "request-disbursement-receipt").await?;
    let result = state
        .g2p
        .request_receipt(
            &connection,
            &g2p_principal(&caller).map_err(HttpError)?,
            key,
            request.instruction_record_id,
            request.instruction_version,
        )
        .await
        .map_err(g2p_error)
        .and_then(|attempt| disbursement_accepted(&attempt));
    finish(
        &state,
        &caller,
        "request-disbursement-receipt",
        None,
        false,
        StatusCode::OK,
        result,
    )
    .await
}

async fn read_disbursement(
    State(state): State<Arc<HttpState>>,
    RoutePath((connection, id)): RoutePath<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, HttpError> {
    let caller = caller(&state, &headers).await?;
    if uri.query().is_some() || !bytes.is_empty() {
        return Err(HttpError(Error::InvalidRequest));
    }
    g2p_connection(&state, &connection, &caller, "read-disbursement").await?;
    let id = collection(&id)?;
    let result = state
        .g2p
        .disbursement_status(&connection, &g2p_principal(&caller).map_err(HttpError)?, id)
        .await
        .map_err(g2p_error)
        .and_then(|attempt| disbursement_status(&attempt));
    finish(
        &state,
        &caller,
        "read-disbursement",
        Some(id),
        false,
        StatusCode::OK,
        result,
    )
    .await
}

async fn record_provider_confirmation(
    State(state): State<Arc<HttpState>>,
    RoutePath((connection, id)): RoutePath<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, HttpError> {
    let caller = caller(&state, &headers).await?;
    let id = collection(&id)?;
    let request: RecordProviderConfirmation = body(&headers, &uri, &bytes)?;
    if request.disbursement_id != id {
        return Err(HttpError(Error::InvalidRequest));
    }
    let key = single_header(&headers, "idempotency-key")?;
    if !super::config::text(key, 128) {
        return Err(HttpError(Error::InvalidRequest));
    }
    g2p_connection(&state, &connection, &caller, "record-provider-confirmation").await?;
    let result = state
        .g2p
        .record_provider_confirmation(
            &connection,
            &g2p_principal(&caller).map_err(HttpError)?,
            key,
            id,
        )
        .await
        .map_err(g2p_error)
        .and_then(|attempt| {
            if attempt.state != G2pAttemptState::ConfirmationRecorded {
                return Err(Error::RecoveryHeld);
            }
            let status = disbursement_status(&attempt)?;
            let confirmation = ProviderConfirmation {
                disbursement_id: id,
                instruction_record_id: attempt.instruction.record_id,
                instruction_id: attempt.instruction.instruction_id,
                instruction_version: attempt.instruction.instruction_version,
                binding_revision: attempt.binding_revision,
                simulation: false,
                money: status.money,
                provider_reference: status.provider_reference.ok_or(Error::Unavailable)?,
                provider_result_digest: attempt.provider_result_digest.ok_or(Error::Unavailable)?,
            };
            confirmation.validate().map_err(|_| Error::Unavailable)?;
            Ok(confirmation)
        });
    finish(
        &state,
        &caller,
        "record-provider-confirmation",
        Some(id),
        true,
        StatusCode::OK,
        result,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn finish<T: Serialize>(
    state: &HttpState,
    caller: &Caller,
    operation: &str,
    id: Option<Uuid>,
    mutation: bool,
    status: StatusCode,
    result: Result<T, Error>,
) -> Result<Response, HttpError> {
    state
        .service
        .audit_access(caller, operation, id, result.as_ref().err().copied())
        .await
        .map_err(|_| {
            HttpError(if mutation {
                Error::OutcomeUnknown
            } else {
                Error::Unavailable
            })
        })?;
    result
        .map(|value| headers((status, Json(value)).into_response()))
        .map_err(HttpError)
}

struct HttpError(Error);
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let problem = PaymentProblem::from(self.0);
        let status =
            StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = (status, Json(problem)).into_response();
        response.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("application/problem+json"),
        );
        headers(response)
    }
}
fn headers(mut response: Response) -> Response {
    let trace = format!(
        "00-{}-{}-00",
        Uuid::new_v4().simple(),
        &Uuid::new_v4().simple().to_string()[..16]
    );
    response.headers_mut().insert(
        "traceparent",
        HeaderValue::from_str(&trace).expect("UUID hex produces a valid trace header"),
    );
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}
fn refused(message: &str) -> ServeError {
    ServeError::Configuration(format!("adapter.payment.configuration: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_auth_match_is_exact_for_each_generic_payment_direction() {
        let pack = PaymentProviderPack::from_yaml(
            format!(
                r#"apiVersion: id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1
kind: AdapterPaymentProviderPack
id: auth-contract
version: '1'
connector: adapter-payment-http/v1
capabilities: [collection, disbursement]
mapping:
  collection:
    auth: bearer
    submit:
      path: /collect
      request: {{file: scripts/provider.rhai, entrypoint: collection_request}}
      response: {{file: scripts/provider.rhai, entrypoint: collection_response}}
  disbursement:
    auth: mifos-legacy-signature
    submit:
      path: /disburse
      request: {{file: scripts/provider.rhai, entrypoint: disbursement_request}}
      response: {{file: scripts/provider.rhai, entrypoint: disbursement_response}}
  scripts:
    - path: scripts/provider.rhai
      digest: sha256:{}
"#,
                "0".repeat(64)
            )
            .as_bytes(),
        )
        .unwrap();
        let mapping = pack.mapping.as_ref().unwrap();
        assert!(mapping_auth_matches(
            mapping.collection.as_ref(),
            PaymentProviderAuth::Bearer,
        ));
        assert!(!mapping_auth_matches(
            mapping.collection.as_ref(),
            PaymentProviderAuth::MifosLegacySignature,
        ));
        assert!(mapping_auth_matches(
            mapping.disbursement.as_ref(),
            PaymentProviderAuth::MifosLegacySignature,
        ));
        assert!(!mapping_auth_matches(
            mapping.disbursement.as_ref(),
            PaymentProviderAuth::Bearer,
        ));
        assert!(!mapping_auth_matches(None, PaymentProviderAuth::Bearer));
    }

    #[test]
    fn startup_accepts_only_authentication_profiles_with_host_implementations() {
        assert!(live_disbursement_auth_supported(
            PaymentProviderAuth::Bearer
        ));
        assert!(live_disbursement_auth_supported(
            PaymentProviderAuth::MifosLegacySignature
        ));
    }

    #[test]
    fn startup_keeps_multiple_exact_pack_pins_for_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let pack_bytes = |version: &str| {
            format!(
                "apiVersion: {}\nkind: {}\nid: sample-payments\nversion: '{version}'\nconnector: simulator-p2g/v1\ncapabilities: [collection]\n",
                super::super::pack::API_VERSION,
                super::super::pack::KIND,
            )
            .into_bytes()
        };
        let first = directory.path().join("first.yaml");
        let second = directory.path().join("second.yaml");
        let first_bytes = pack_bytes("1");
        let second_bytes = pack_bytes("2");
        std::fs::write(&first, &first_bytes).unwrap();
        std::fs::write(&second, &second_bytes).unwrap();
        let loaded = load_provider_packs(&[first.clone(), second.clone()]).unwrap();
        let pin = |version: &str, bytes: &[u8]| super::super::pack::ProviderPackPin {
            id: "sample-payments".to_owned(),
            version: version.to_owned(),
            digest: registry_platform_config::sha256_uri(bytes),
        };
        assert_eq!(
            loaded.for_pin(&pin("1", &first_bytes)).unwrap().version,
            "1"
        );
        assert_eq!(
            loaded.for_pin(&pin("2", &second_bytes)).unwrap().version,
            "2"
        );
        assert!(loaded.for_pin(&pin("3", &first_bytes)).is_err());
        assert!(load_provider_packs(&[first.clone(), first]).is_err());
        assert!(load_provider_packs(&vec![second; MAX_PAYMENT_PROVIDER_PACKS + 1]).is_err());
    }
}
