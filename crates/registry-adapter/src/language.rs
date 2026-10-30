// SPDX-License-Identifier: Apache-2.0

//! The expression languages, externally tagged by language as in Camel
//! (`products/adapter/CONCEPT.md` section 8.5): `constant`, `header`,
//! and `exchangeProperty` inline; `jsonpath`, RFC 9535, inline, on the
//! IETF standard rather than Jayway's dialect; and `rhai`, a
//! digest-pinned script file and entrypoint through
//! `registry-platform-script`. Camel's Simple language, Groovy,
//! JavaScript, and `bean` are not ported.
//!
//! A predicate is an expression whose result is a boolean; a non-boolean
//! result is an error, never a truthiness guess. A singular JSONPath
//! query (RFC 9535 section 2.3.5) yields its one value, or absent when
//! nothing matches; any other query yields the node list as a JSON
//! array, empty when nothing matches (section 8.11.8).
