// SPDX-License-Identifier: Apache-2.0
//! A deterministic mock [`ScriptSourceHost`] for offline tests.
//!
//! The mock answers every `source.*` call with a configured outcome after a
//! configurable delay. The delay makes cancellation deterministic: a slow mock
//! lets a test prove that the caller deadline is respected and that an
//! in-flight call is abandoned. A monotonically increasing call counter lets
//! tests assert how many calls actually completed.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::error::SourceScriptError;
use crate::host::{ScriptSourceHost, SourceResponse};

/// What the mock returns for a call.
#[derive(Clone)]
enum Outcome {
    /// Echo back the requested `target`/`path`/`value` as a single record.
    Echo { status: u16 },
    /// Return a fixed body with a fixed status.
    Fixed { status: u16, body: Value },
    /// Return a `(status, body)` keyed on the requested `path`, falling back to
    /// `fallback` for any path not present in the map. Lets a test exercise
    /// path-dependent responses (e.g. 404 on `/a`, 200 on `/b`).
    ByPath {
        responses: std::collections::BTreeMap<String, (u16, Value)>,
        fallback: (u16, Value),
    },
    /// Fail at the transport layer.
    Transport,
}

/// A configurable, deterministic source host for tests.
#[derive(Clone)]
pub struct MockScriptHost {
    delay: Duration,
    outcome: Outcome,
    /// Number of source calls that ran to completion (not cancelled).
    pub calls_completed: Arc<AtomicU64>,
    /// Number of source calls that were started.
    pub calls_started: Arc<AtomicU64>,
}

impl MockScriptHost {
    /// A host that echoes the request as `[{ "id": "<target><path>", "v": <value> }]`
    /// with status 200, after `delay`.
    pub fn echo(delay: Duration) -> Self {
        Self {
            delay,
            outcome: Outcome::Echo { status: 200 },
            calls_completed: Arc::new(AtomicU64::new(0)),
            calls_started: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A host that returns a fixed `body` with `status` after `delay`.
    pub fn fixed(delay: Duration, status: u16, body: Value) -> Self {
        Self {
            delay,
            outcome: Outcome::Fixed { status, body },
            calls_completed: Arc::new(AtomicU64::new(0)),
            calls_started: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A host that returns a `(status, body)` keyed on the requested `path`,
    /// using `fallback` for any path not in `responses`, after `delay`. Useful
    /// for path-dependent flows such as a 404-on-`/a`, 200-on-`/b` fallback.
    pub fn by_path(
        delay: Duration,
        responses: std::collections::BTreeMap<String, (u16, Value)>,
        fallback: (u16, Value),
    ) -> Self {
        Self {
            delay,
            outcome: Outcome::ByPath {
                responses,
                fallback,
            },
            calls_completed: Arc::new(AtomicU64::new(0)),
            calls_started: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A host that always fails at the transport layer after `delay`.
    pub fn transport_failure(delay: Duration) -> Self {
        Self {
            delay,
            outcome: Outcome::Transport,
            calls_completed: Arc::new(AtomicU64::new(0)),
            calls_started: Arc::new(AtomicU64::new(0)),
        }
    }

    /// How many calls ran to completion (were not cancelled mid-flight).
    pub fn completed(&self) -> u64 {
        self.calls_completed.load(Ordering::SeqCst)
    }

    /// How many calls were started.
    pub fn started(&self) -> u64 {
        self.calls_started.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ScriptSourceHost for MockScriptHost {
    async fn source_get(
        &self,
        target: &str,
        path: &str,
        query: Value,
    ) -> Result<SourceResponse, SourceScriptError> {
        self.respond(target, path, query, Value::Null).await
    }

    async fn source_post_json(
        &self,
        target: &str,
        path: &str,
        query: Value,
        body: Value,
    ) -> Result<SourceResponse, SourceScriptError> {
        self.respond(target, path, query, body).await
    }
}

impl MockScriptHost {
    async fn respond(
        &self,
        target: &str,
        path: &str,
        query: Value,
        body: Value,
    ) -> Result<SourceResponse, SourceScriptError> {
        self.calls_started.fetch_add(1, Ordering::SeqCst);
        // If this future is dropped during the sleep (cancellation), the
        // completion counter is NOT incremented — that is how a test proves the
        // call was abandoned.
        tokio::time::sleep(self.delay).await;
        self.calls_completed.fetch_add(1, Ordering::SeqCst);

        match &self.outcome {
            Outcome::Transport => Err(SourceScriptError::HttpTransport),
            Outcome::Echo { status } => Ok(SourceResponse {
                status: *status,
                body: json!([
                    {
                        "id": format!("{target}{path}"),
                        "v": query.get("value").cloned().unwrap_or(Value::Null),
                        "body": body,
                    }
                ]),
            }),
            Outcome::Fixed { status, body } => Ok(SourceResponse {
                status: *status,
                body: body.clone(),
            }),
            Outcome::ByPath {
                responses,
                fallback,
            } => {
                let (status, body) = responses.get(path).unwrap_or(fallback);
                Ok(SourceResponse {
                    status: *status,
                    body: body.clone(),
                })
            }
        }
    }
}
