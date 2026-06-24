// SPDX-License-Identifier: Apache-2.0
//! Entity-grain metadata renderers.
//!
//! The public REST model is the entity registry, while `Config`
//! carries human metadata and semantic annotations. This module joins
//! those two views into stable JSON documents for metadata routes.
//!
//! These renderers power Registry Relay's own route surface
//! (`/v1/datasets/.../schema`, the generated OpenAPI document) and emit a
//! Relay-specific vocabulary (`belongs_to`/`has_many`/`has_one`,
//! `{base}/v1/datasets/{ds}/entities/{entity}/fields/{name}` URLs). Standards-facing
//! renderers (DCAT-AP, BRegDCAT-AP, SHACL, JSON Schema Draft 2020-12)
//! live in `registry-manifest-core` and are reached via the
//! `core_adapter` submodule for routes mounted under `/metadata/*`.
//! Both stacks read the same `Config` source of truth; divergence is
//! intentional at the wire-shape boundary.

pub mod catalog;
pub mod core_adapter;
pub mod shacl;

pub use catalog::catalog_document;
pub use core_adapter::{
    compiled_from_runtime, manifest_from_runtime, scoped_compiled_from_runtime,
};
pub use shacl::{
    dcat_ap_document, dcat_ap_document_for_dataset_ids, dcat_ap_document_for_entity_ids,
    entity_schema_document,
};
