// SPDX-License-Identifier: Apache-2.0

//! The `split` processor, Camel's Splitter
//! (`products/adapter/CONCEPT.md` section 8.6).
//!
//! Ported: `expression`, `aggregationStrategy` (default returns the
//! original message), `stopOnException` (default false), the failure
//! accounting of `errorThreshold` and `maxFailedRecords`, and the
//! exchange headers `CamelSplitIndex`, `CamelSplitSize`,
//! `CamelSplitComplete`, and `CamelSplitResult`. Not ported:
//! `parallelProcessing`, `streaming`, and `timeout`. `maximumItems` is
//! mandatory.
