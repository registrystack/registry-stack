// SPDX-License-Identifier: Apache-2.0

//! The `filter` processor, Camel's Message Filter
//! (`products/adapter/CONCEPT.md` section 8.6): the nested steps run
//! only on a matching predicate, `CamelFilterMatched` records the
//! outcome, and the route continues after the filter either way.
