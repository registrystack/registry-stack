// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary tests that do not link Registry Relay.

#[path = "standalone_http/admin.rs"]
mod admin;
#[path = "standalone_http/audit.rs"]
mod audit;
#[path = "standalone_http/auth.rs"]
mod auth;
#[path = "standalone_http/credentials.rs"]
mod credentials;
#[path = "standalone_http/federation.rs"]
mod federation;
#[path = "standalone_http/http_contracts.rs"]
mod http_contracts;
#[path = "standalone_http/oid4vci.rs"]
mod oid4vci;
#[path = "standalone_http/preauth.rs"]
mod preauth;
#[path = "standalone_http/sources.rs"]
mod sources;
#[path = "standalone_http/support.rs"]
mod support;
