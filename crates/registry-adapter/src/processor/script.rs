// SPDX-License-Identifier: Apache-2.0

//! The `script` processor: run an expression for effect on exchange
//! properties without changing the body, as Camel's `script` EIP
//! (`products/adapter/CONCEPT.md` section 8.6).
//!
//! The `rhai` entrypoint receives the exchange view of section 8.11.3
//! and returns a map of property names to values. Each script file is
//! its own compilation unit and the budgets are
//! `registry-platform-script`'s; exceeding one raises the uncatchable
//! `script.budget-exceeded`.
