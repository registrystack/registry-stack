// SPDX-License-Identifier: Apache-2.0

//! The `doTry`, `doCatch`, and `doFinally` processors, ported as in
//! Camel (`products/adapter/CONCEPT.md` section 8.7). A `doCatch`
//! narrows with `onWhen`, and no clause may name an uncatchable class:
//! when an uncatchable class is in the error's cause chain, no clause
//! fires at all, whatever the other causes are.
