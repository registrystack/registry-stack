// SPDX-License-Identifier: Apache-2.0
//! HTTP API routers.
//!
//! Wave 0 ships the health/ready routes (this module's `health`
//! submodule). Entity-shaped route declarations are exposed here for
//! Wave 2 integration while query execution remains decoupled. Catalog
//! route declarations are exposed for the metadata slice; the remaining
//! data-plane endpoints documented in Spec.md Section 7
//! (`/admin/reload`, `/openapi.json`) land in Waves 2-4 as their owning
//! tracks register routes here.
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

pub use admin::router as admin_router;
pub use aggregates::router as aggregates_router;
pub use catalog::router as catalog_router;
pub use datasets::router as datasets_router;
pub use entity::router as entity_router;
pub use health::router as health_router;
