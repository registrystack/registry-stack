//! HTTP security primitives shared by Registry Stack servers and clients.

mod bearer;
mod client;
pub use registry_platform_loopback as loopback;

pub use bearer::bearer_challenge;
pub use client::{
    response_trace_id, ProblemDocument, ProblemDocumentError, ResponseTraceError, TraceId,
    TraceIdError,
};

#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
pub use server::*;

#[cfg(feature = "refusal-trace-id")]
pub mod refusal_detail;
