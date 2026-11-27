// SPDX-License-Identifier: Apache-2.0

//! A small session service beside a gateway.
//!
//! A person signs in once through the service. It keeps their tokens on the
//! server and gives the browser one opaque cookie. The gateway asks the service,
//! on every call to a signed-in route, which bearer token to attach: the service
//! checks, it never proxies.

pub mod config;
