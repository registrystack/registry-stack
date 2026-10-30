// SPDX-License-Identifier: Apache-2.0

//! The exchange and message model, ported from Camel's `Exchange` and
//! `Message` (`products/adapter/CONCEPT.md` section 8.2).
//!
//! An exchange carries an exchange id, an `InOut` message pattern, one
//! message of headers and body, exchange properties, and an exception
//! slot. Headers are a bounded, case-insensitive map; the body is a
//! size-bounded JSON value once unmarshalled; the `http` component
//! marshals and unmarshals JSON itself instead of Camel's explicit
//! `marshal` and `unmarshal` steps, because the components speak exactly
//! one data format.
//!
//! What enters the exchange is declared: the `rest` consumer places only
//! the bound operation's validated inputs on it, under the closed names
//! of section 8.11.1, and credentials, base URLs, and secrets never
//! enter it, so no expression or header can carry them out.
