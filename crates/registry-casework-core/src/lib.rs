//! Source-neutral contracts for Registry Casework.
//!
//! The crate deliberately contains no source protocol types. Source adapters
//! translate their native reads, promoted actions, receipts, and recovery
//! records at this boundary.

mod adapter;
mod assignment;
mod calendar;
mod clock_runtime;
mod config;
mod hosted;
mod http;
mod model;
mod policy;
mod routing;
mod source_retention;
mod timing;
mod transition;

pub use adapter::*;
pub use assignment::*;
pub use calendar::*;
pub use clock_runtime::*;
pub use config::*;
pub use hosted::*;
pub use http::*;
pub use model::*;
pub use policy::*;
pub use routing::*;
pub use source_retention::*;
pub use timing::*;
pub use transition::*;
