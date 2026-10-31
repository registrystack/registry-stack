// SPDX-License-Identifier: Apache-2.0
//! The BReg connector: read and lookup, direct mutation, immediate
//! Action, Proposal Action, and batch and ingestion runs, over
//! `registry-breg-client` (`products/adapter/CONCEPT.md` section 17.3).
//!
//! Each family lands in its own module under `breg/`; `catalog()`
//! advertises exactly the implemented, enabled operations.
