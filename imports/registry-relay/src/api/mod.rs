// SPDX-License-Identifier: Apache-2.0
//! HTTP API routers.
//!
//! This module exposes one router entry point per API area. The public
//! data-plane router mounts health, readiness, datasets, entity rows,
//! relationships, aggregates, portable metadata, and OpenAPI. Admin
//! routes are exported separately so `server::build_admin_app` can mount
//! them only on the optional `server.admin_bind` listener.
//!
//! Route assembly lives in `server::build_app`; this module's job is to
//! expose a clean, single-call entry point per feature area so the
//! server wiring stays terse.

pub mod admin;
pub mod aggregates;
pub mod contexts;
pub mod datasets;
pub mod did;
pub mod docs;
pub mod entity;
pub(crate) mod governed;
pub mod health;
pub mod metadata;
#[cfg(any(
    feature = "ogcapi-features",
    feature = "ogcapi-records",
    feature = "ogcapi-edr"
))]
pub mod ogc;
pub mod openapi;
pub(crate) mod provenance_issuance;
pub mod schemas;
#[cfg(feature = "spdci-api-standards")]
pub mod spdci;

pub use crate::runtime_config::CursorSigner;
pub use admin::router as admin_router;
pub use aggregates::router as aggregates_router;
pub use contexts::router as contexts_router;
pub use datasets::router as datasets_router;
pub use did::router as did_router;
pub use docs::router as docs_router;
pub use entity::router as entity_router;
pub use health::router as health_router;
pub use metadata::router as metadata_router;
pub use metadata::well_known_router;
#[cfg(feature = "ogcapi-edr")]
pub use ogc::edr_router;
#[cfg(feature = "ogcapi-features")]
pub use ogc::features_router as ogc_router;
#[cfg(feature = "ogcapi-records")]
pub use ogc::records_router;
pub use openapi::router as openapi_router;
pub use schemas::router as schemas_router;
#[cfg(feature = "spdci-api-standards")]
pub use spdci::router as spdci_router;
