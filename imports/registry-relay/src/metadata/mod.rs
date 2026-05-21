// SPDX-License-Identifier: Apache-2.0
//! Entity-grain metadata renderers.
//!
//! The public REST model is the entity registry, while `Config`
//! carries human metadata and semantic annotations. This module joins
//! those two views into stable JSON documents for metadata routes.

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
