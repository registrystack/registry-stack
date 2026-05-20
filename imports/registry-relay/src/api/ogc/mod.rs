// SPDX-License-Identifier: Apache-2.0
//! OGC API route modules.

#[cfg(feature = "ogcapi-features")]
pub mod features;
#[cfg(feature = "ogcapi-records")]
pub mod records;

#[cfg(feature = "ogcapi-features")]
pub use features::router as features_router;
#[cfg(feature = "ogcapi-records")]
pub use records::router as records_router;
