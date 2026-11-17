// SPDX-License-Identifier: Apache-2.0

//! The `setProperty` processor: set an exchange property from an
//! expression.
//!
//! The read-only facade inputs are refused as targets,
//! except `AdapterNextContinuation`, which exists to be set: a search
//! route sets it to the upstream position the engine encodes for the
//! caller as the opaque cursor. Absent or `null` at
//! the end of the route means the last page.
