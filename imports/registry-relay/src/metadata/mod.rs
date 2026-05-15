// SPDX-License-Identifier: Apache-2.0
//! Entity-grain metadata renderers.
//!
//! The public REST model is the entity registry, while `Config`
//! carries human metadata and semantic annotations. This module joins
//! those two views into stable JSON documents for catalog routes.

pub mod catalog;
pub mod shacl;

pub use catalog::catalog_document;
pub use shacl::{dcat_ap_document, entity_shape_document};
