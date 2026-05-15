// SPDX-License-Identifier: Apache-2.0
//! HTTP API routers.
//!
//! This module exposes one router entry point per API area. The public
//! data-plane router mounts health, readiness, datasets, entity rows,
//! relationships, aggregates, catalog metadata, and OpenAPI. Admin
//! routes are exported separately so `server::build_admin_app` can mount
//! them only on the optional `server.admin_bind` listener.
//!
//! Route assembly lives in `server::build_app`; this module's job is to
//! expose a clean, single-call entry point per feature area so the
//! server wiring stays terse.

pub mod admin;
pub mod aggregates;
pub mod catalog;
pub mod datasets;
pub mod entity;
pub mod health;
pub mod openapi;

pub use admin::router as admin_router;
pub use aggregates::router as aggregates_router;
pub use catalog::router as catalog_router;
pub use datasets::router as datasets_router;
pub use entity::router as entity_router;
pub use entity::CursorSigner;
pub use health::router as health_router;
pub use openapi::router as openapi_router;
