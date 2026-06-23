// SPDX-License-Identifier: Apache-2.0
//! The language-agnostic async host seam.
//!
//! [`ScriptSourceHost`] is the single boundary between a sandboxed script and
//! the outside world. A script can only ever request `source.get(...)`; the
//! engine routes that request through this trait. The trait is intentionally
//! minimal and effect-oriented so an embedder can back it with a real HTTP
//! client, while tests back it with a deterministic mock.

use crate::error::SourceScriptError;

/// The result of a single host `source.get` call.
///
/// The engine surfaces a returned `Ok(SourceResponse)` to the script as a
/// `#{ status, body }` map when the status is *observable* — 2xx, or in the
/// engine's configured `visible_statuses`. A non-observable non-2xx status
/// terminates the run as an upstream-status error. A host returns `Err` only for
/// transport failures or denials, never to signal an ordinary HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceResponse {
    /// The upstream HTTP status code.
    pub status: u16,
    /// The decoded response body as JSON.
    pub body: serde_json::Value,
}

/// The host capability a script may invoke as `source.get(target, path, query)`.
///
/// Implementations own *all* effects: authentication, base-URL joining,
/// allow-listing, and the actual network call. The script never sees any of
/// that; it only receives a [`SourceResponse`] or a [`SourceScriptError`].
#[async_trait::async_trait]
pub trait ScriptSourceHost: Send + Sync {
    /// Perform a single source read.
    ///
    /// The engine surfaces a returned `Ok(SourceResponse)` to the script as
    /// `#{ status, body }` when the status is observable (2xx or in the engine's
    /// configured `visible_statuses`); a non-observable non-2xx status
    /// terminates the run as an upstream-status error. Return `Err` only for
    /// transport failures or denials.
    ///
    /// * `target` — the logical upstream identifier the script selected.
    /// * `path` — a target-relative request path. The engine has already run it
    ///   through [`canonicalize_target_relative_path`](crate::canonicalize_target_relative_path)
    ///   before calling this method: it begins with a single `/`, contains no
    ///   `.`/`..`/empty segments, no query or fragment, no backslash, no
    ///   encoded separator, and no surviving percent-escape. An implementation
    ///   still owns base-URL joining and allow-listing, but need not re-validate
    ///   the path's structural safety.
    /// * `query` — a JSON object of query parameters supplied by the script.
    async fn source_get(
        &self,
        target: &str,
        path: &str,
        query: serde_json::Value,
    ) -> Result<SourceResponse, SourceScriptError>;
}
