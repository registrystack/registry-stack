// SPDX-License-Identifier: Apache-2.0

//! The `to` processor: send the exchange to an endpoint.
//!
//! The URI is static and `toD` is not ported. An `http` send may follow
//! an origin-pinned link the source returned through `httpUri`. A send's safety comes from its HTTP method; a
//! `POST` whose endpoint operation declares `safeUpstream: true`, a
//! reviewed claim, counts as safe for the write-safety rules. Redelivery
//! reaches endpoint sends only, never a `to: direct:` send.
