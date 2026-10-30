// SPDX-License-Identifier: Apache-2.0

//! The `enrich` processor, Camel's Content Enricher
//! (`products/adapter/CONCEPT.md` sections 8.6 and 8.11.7).
//!
//! The resource send runs on a copy of the exchange, and the reply
//! merges back through the `aggregationStrategy`, which by default
//! replaces the body with the resource reply. `aggregateOnException`
//! (default false) sends the failure to the error handler instead, so a
//! record is never served without its enrichment unless the pack
//! handles the failure. The built-in strategies merge bodies only:
//! properties set by the resource route are carried out of the reply
//! only where the strategy names them through `properties`, a map from
//! property name to a JSONPath on the reply, which is how a pagination
//! loop carries the next cursor or link.
