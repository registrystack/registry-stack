// SPDX-License-Identifier: Apache-2.0

//! The `rest` consumer: the facade, ported from Camel's contract-first
//! REST DSL (`rest().openApi()`).
//!
//! The generated OpenAPI is the specification; every concrete operation
//! dispatches to its bound route, `clientRequestValidation` is always
//! on, unmatched requests answer 404 or 405 as in Camel, and a missing
//! route fails startup (Camel's `missingOperation` default; `ignore` and
//! `mock` are not ported). Serving is an axum listener
//! with OIDC and the access profiles. The consumer
//! places only the validated facade inputs on the
//! exchange, under closed, profile-neutral names, and fills the
//! profile's response envelope templates.
//!
//! # Continuation cursor codec
//!
//! The continuation codec lives in this module as
//! `continuation.rs`: the engine seals the value a search route sets on
//! `AdapterNextContinuation` as the opaque `nextCursor` slot,
//! authenticated-encrypted under the runtime secret `cursorKeyRef` and
//! bound to the concrete operation, the binding id, the caller's
//! authenticated issuer and subject, the deployment the runtime serves,
//! a digest of the filters and page size, and an expiry
//! (`cursorTtlSeconds`, default 900), with the optional
//! `previousCursorKeyRef` keeping cursors valid across one key rotation.
//! A cursor that fails authentication, has expired, or was minted for
//! another operation, caller, or filter set raises
//! `facade.invalid-cursor` before any route step runs.
//!
//! [`continuation`] records the AEAD it seals with and the reason for
//! that choice. The codec is security-sensitive (it carries source
//! state through the caller).

pub mod continuation;
