// SPDX-License-Identifier: Apache-2.0
//! HTTP API routers.
//!
//! Wave 0 ships only the health/ready routes (this module's `health`
//! submodule). The data-plane endpoints documented in Spec.md Section 7
//! (`/catalog`, `/datasets/...`, `/admin/reload`, `/openapi.json`) land
//! in Waves 1-4 as their owning tracks register routes here.
//!
//! Route assembly lives in `server::build_app`; this module's job is to
//! expose a clean, single-call entry point per feature area so the
//! server wiring stays terse.

pub mod health;

pub use health::router as health_router;
