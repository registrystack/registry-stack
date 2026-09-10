//! Source-neutral contracts for Registry Casework.
//!
//! The crate deliberately contains no source protocol types. Source adapters
//! translate their native reads, promoted actions, receipts, and recovery
//! records at this boundary.

mod adapter;
mod assignment;
mod config;
mod hosted;
mod http;
mod model;
mod timing;
mod transition;

pub use adapter::*;
pub use assignment::*;
pub use config::*;
pub use hosted::*;
pub use http::*;
pub use model::*;
pub use timing::*;
pub use transition::*;
