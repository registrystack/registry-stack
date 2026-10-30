// SPDX-License-Identifier: Apache-2.0

//! The `transform` processor, Camel's message transformation sugar over
//! `setBody` (`products/adapter/CONCEPT.md` section 8.6). It replaces
//! the body with its expression's value under the same rules as
//! `crate::processor::set_body`.
