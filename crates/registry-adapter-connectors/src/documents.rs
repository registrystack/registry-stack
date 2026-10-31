// SPDX-License-Identifier: Apache-2.0
//! The Document Store connector: policy and metadata, reserve and
//! upload, exact-version download, grants, and explicit erasure, over
//! `registry-documents-client` (`products/adapter/CONCEPT.md`
//! section 17.3).
//!
//! Binary content moves through an opaque host-owned content reference
//! with digest, length, and media type, never base64 through a mapping.
//! The module is off by default: Document Store is held out of 1.0.
