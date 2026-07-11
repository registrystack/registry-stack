use axum::{
    body::{to_bytes, Body},
    extract::{Path, Query, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use crosswalk_core::{MappingRuntime, RuntimeOptions, StandaloneExpressionInput};
use hyper::service::service_fn;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as HyperBuilder,
};
use registry_notary_source_adapter_rhai::{
    Lookup, RhaiLimits, RhaiPolicy, ScriptCtx, ScriptEngine, ScriptSourceHost, SourceResponse,
    SourceScriptError,
};
use registry_platform_audit::{AuditProfile, ChainState, JsonlFileSink};
use registry_platform_authcommon::{parse_bearer_token, parse_fingerprint, verify_api_key};
use registry_platform_httputil::is_cloud_metadata_ip;
use registry_platform_ops::{AntiRollbackKey, AntiRollbackProposal, FileAntiRollbackStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::Infallible,
    fmt,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{watch, Mutex, OnceCell, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tower::ServiceExt;
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use tracing::{info, warn};

#[path = "audit_metrics.rs"]
mod audit_metrics;
#[path = "auth.rs"]
mod auth;
#[path = "config.rs"]
mod config;
#[path = "egress/mod.rs"]
mod egress;
#[path = "engine_common.rs"]
mod engine_common;
#[path = "error.rs"]
mod error;
#[path = "fhir_engine.rs"]
mod fhir_engine;
#[path = "governed.rs"]
mod governed;
#[path = "handlers.rs"]
mod handlers;
#[path = "http_flow_engine.rs"]
mod http_flow_engine;
#[path = "http_json_engine.rs"]
mod http_json_engine;
#[path = "normalization.rs"]
mod normalization;
#[path = "rhai_engine.rs"]
mod rhai_engine;
#[path = "server.rs"]
mod server;
#[path = "state.rs"]
mod state;
#[path = "validation.rs"]
mod validation;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

use audit_metrics::*;
use auth::*;
use config::*;
use egress::*;
use engine_common::*;
use fhir_engine::*;
use governed::*;
use handlers::*;
use http_flow_engine::*;
use http_json_engine::*;
use normalization::*;
use rhai_engine::*;
use server::*;
use state::*;
use validation::*;

pub use config::SidecarConfig;
pub use error::SidecarError;
pub use governed::{
    load_startup_config, load_startup_config_with_options, render_governed_runtime_target_json,
    verify_governed_bundle_report_json,
};
pub use server::{run, sidecar_router};

async fn execute_source_json(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    match source.engine {
        SourceEngine::HttpJson => execute_http_json(state, source_id, source, request).await,
        SourceEngine::HttpFlow => execute_http_flow(state, source_id, source, request).await,
        SourceEngine::Fhir => execute_fhir(state, source_id, source, request).await,
        SourceEngine::ScriptRhai => execute_rhai(state, source_id, source, request).await,
    }
}
