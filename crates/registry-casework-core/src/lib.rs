//! Source-neutral contracts for Registry Casework.
//!
//! The crate deliberately contains no source protocol types. Source adapters
//! translate their native reads, promoted actions, receipts, and recovery
//! records at this boundary.

mod adapter;
mod assignment;
mod attempt_settlement;
mod clock_runtime;
mod config;
mod hosted;
mod http;
mod model;
mod policy;
mod routing;
mod source_retention;
mod task_grant;
mod timing;
mod transition;

pub use adapter::*;
pub use assignment::*;
pub use attempt_settlement::*;
pub use clock_runtime::*;
pub use config::*;
pub use hosted::*;
pub use http::*;
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
pub use routing::*;
pub use source_retention::*;
pub use task_grant::*;
pub use timing::*;
pub use transition::*;
