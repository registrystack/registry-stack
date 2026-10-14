//! Source-neutral contracts for Registry Casework.
//!
//! The crate deliberately contains no source protocol types. Context providers
//! expose separate, read-only observations for each compiled purpose.

mod adapter;
mod assignment;
mod clock_runtime;
mod config;
mod context;
mod finding;
mod fixture;
mod http;
mod lifecycle;
mod model;
mod policy;
mod review;
mod routing;
#[cfg(feature = "schema")]
pub mod schema;
mod staffing;
mod task_grant;
mod timing;
pub mod typed;

pub use adapter::*;
pub use assignment::*;
pub use clock_runtime::*;
pub use config::*;
pub use context::*;
pub use finding::{findings_report, ConfigFinding, RelatedFinding};
pub use fixture::*;
pub use http::*;
pub use lifecycle::*;
pub use model::*;
pub use policy::*;
// Casework's clocks are working-day deadlines, so it re-exports that
// evaluator and nothing else. The weekly opening-pattern evaluator in the
// same platform crate serves a different product and is not Casework's to
// publish.
pub use registry_platform_calendar::{
    evaluate_working_day_deadline, CalendarEvaluationError, HolidaySetRevision, WorkingCalendar,
    WorkingDayDeadline, WorkingDayDeadlineRule, MAXIMUM_WORKING_DAY_OFFSET,
};
pub use registry_review_protocol as review_protocol;
pub use registry_review_protocol::*;
pub use review::*;
pub use routing::*;
pub use staffing::*;
pub use task_grant::*;
pub use timing::*;
