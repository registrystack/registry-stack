// SPDX-License-Identifier: Apache-2.0

//! The `setHeader` processor: set a message header from an expression
//! (`products/adapter/CONCEPT.md` section 8.6).
//!
//! The read-only facade inputs of section 8.11.1 are refused as targets.
//! A `header` expression may read only a facade input header, a declared
//! response header, a Camel engine header the engine sets, or a header
//! an earlier step of the same route set (section 8.11.4).
