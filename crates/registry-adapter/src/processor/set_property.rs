// SPDX-License-Identifier: Apache-2.0

//! The `setProperty` processor: set an exchange property from an
//! expression (`products/adapter/CONCEPT.md` section 8.6).
//!
//! The read-only facade inputs of section 8.11.1 are refused as targets,
//! except `AdapterNextContinuation`, which exists to be set: a search
//! route sets it to the upstream position the engine encodes for the
//! caller as the opaque cursor of section 8.11.2. Absent or `null` at
//! the end of the route means the last page.
