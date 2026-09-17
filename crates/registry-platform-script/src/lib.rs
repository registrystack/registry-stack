// SPDX-License-Identifier: Apache-2.0
//! Bounded script execution mechanics shared across Registry Stack products.
//!
//! The crate is a narrow execution facade with one module per backend. It owns
//! how reviewed script source is prepared and run under explicit resource
//! limits; the owning product decides what its scripts mean. Products keep
//! entry-point names, helper inventories, source-review policy, every input and
//! output conversion, result validation, cancellation handling, and every
//! public error. Product adapters may name backend types directly: there is
//! deliberately no engine-neutral facade and no requirement to pass values
//! through JSON. Both engine lifetimes are first class: a product may construct
//! a fresh engine per call or retain one engine and its registration surface
//! for the process lifetime.
//!
//! The WASM backend module and its duplicate-JSON-member outcome check are
//! compiled only under the crate's non-default `wasm` feature; without it the
//! crate is the Rhai adapter alone.

#[cfg(feature = "wasm")]
pub mod json_check;
pub mod rhai;
#[cfg(feature = "wasm")]
pub mod wasm;
