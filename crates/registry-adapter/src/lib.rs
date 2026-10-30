// SPDX-License-Identifier: Apache-2.0

//! Runtime of the Registry Stack Adapter.
//!
//! This crate serves the Adapter's governed facade, executes call plans
//! against declared upstreams, and owns its security surface and audit
//! journal (`products/adapter/CONCEPT.md` section 8.1). One execution per
//! facade call validates the request against the declared model, resolves
//! the operation binding, interprets the bound plan step by step, and
//! journals metadata for every step before answering.
//!
//! The upstream transport reuses `registry-platform-httputil`'s fixed
//! destination policy and destination scripts, the facade server side
//! uses `registry-platform-httpsec`, and throttling, configuration,
//! audit, and artifact reading reuse the corresponding platform crates;
//! the adapter inherits no authorization from any caller or upstream.
//! The source-neutral model this runtime interprets lives in
//! `registry-adapter-core`; operator tooling lives in
//! `registry-adapterctl`.
//!
//! The engine lives in the modules named for Camel's concepts
//! (`products/adapter/CONCEPT.md` section 8.1): `exchange` and `route`
//! hold the exchange and route models, `processor` one submodule per
//! EIP with the aggregation strategies, `component` the `direct`,
//! `http`, and `rest` components, `language` the expression languages,
//! `errorhandler` the error classes and handlers, `journal` the
//! journal's PostgreSQL store and migration, `notifier` the
//! journal, and `idempotent` the idempotency store.
//!
//! The `auth` module is the outbound authentication layer
//! (`products/adapter/CONCEPT.md` section 10.2): one endpoint's
//! declared credential kind compiles against its runtime binding before
//! any secret is resolved, secrets live only in zeroizing buffers from
//! resolution through the outbound request, the OAuth2 kinds acquire and
//! cache bearer credentials through the endpoint's fixed token endpoint
//! under the exchange's token budget, and a late 401 refreshes only the
//! issuance the refused send carried. Every fault maps to a section 8.7
//! class, and the journal keeps only value-free auth events.

pub mod auth;
pub mod component;
pub mod errorhandler;
pub mod exchange;
pub mod idempotent;
pub mod journal;
pub mod language;
pub mod notifier;
pub mod processor;
pub mod route;
