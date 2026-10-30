// SPDX-License-Identifier: Apache-2.0

//! The `setBody` processor: replace the message body with the value of
//! its expression (`products/adapter/CONCEPT.md` section 8.6).
//!
//! The expression is one of the languages of section 8.5. An absent
//! JSONPath result raises the `validation` class where a value is
//! required (section 8.11.8).
