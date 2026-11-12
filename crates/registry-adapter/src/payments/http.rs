// SPDX-License-Identifier: Apache-2.0
//! Typed payment routes sharing the Adapter's authentication and database host.

use super::{
    config::{PaymentsConfig, API_VERSION, KIND},
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
    PaymentProblem, PaymentProblemCode as Error, RecordReceipt, RequestCollection,
};
use registry_platform_config::{
    RuntimeConfigLoader, RuntimeEnvelope, SecretProvider, SecretResolver,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{path::Path, sync::Arc};
use uuid::Uuid;

struct HttpState {
    authenticator: Authenticator,
    service: PaymentService,
}

/// Fixed payment routes and wire schemas, without origins or credential references.
#[cfg(feature = "schema")]
pub fn contract(config: &PaymentsConfig) -> serde_json::Value {
    use registry_payment_protocol::{CollectionAccepted, CollectionStatus, RegistryReceipt};
    serde_json::json!({
        "protocol":"payments/v1",
        "authentication":"OIDC access tokens under the Adapter runtime issuer and client policy",
        "simulation":true,
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
        }).collect::<Vec<_>>(),
        "schemas":{
            "RequestCollection":schemars::schema_for!(RequestCollection),
            "CollectionAccepted":schemars::schema_for!(CollectionAccepted),
            "CollectionStatus":schemars::schema_for!(CollectionStatus),
            "RecordReceipt":schemars::schema_for!(RecordReceipt),
            "RegistryReceipt":schemars::schema_for!(RegistryReceipt),
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

pub async fn load_router(
    runtime: &AdapterRuntimeConfig,
    path: &Path,
    pool: deadpool_postgres::Pool,
) -> Result<Router, ServeError> {
    let config = load_config(path)?;
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
    }
    let store = PaymentStore::new(pool, runtime.id.as_str().to_owned());
    store
        .check_privileges()
        .await
        .map_err(|_| refused("payment runtime role lacks required table or sequence privileges"))?;
    let service = PaymentService::new(
        config,
        store,
        Arc::new(BregBridge::new(resolver.clone())),
        Arc::new(SyntheticProvider::new(resolver)),
    )
    .map_err(|_| refused("payment service was refused"))?;
    let state = Arc::new(HttpState {
        authenticator,
        service,
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
        .layer(DefaultBodyLimit::max(4096))
        .with_state(state))
}

pub async fn run_only(runtime_path: &Path, payments_path: &Path) -> Result<(), ServeError> {
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
    let router = load_router(&runtime, payments_path, pool).await?;
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
        .headers_mut()
        .insert("x-payment-simulator", HeaderValue::from_static("synthetic"));
    response
}
fn refused(message: &str) -> ServeError {
    ServeError::Configuration(format!("adapter.payment.configuration: {message}"))
}
