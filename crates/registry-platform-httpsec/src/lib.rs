//! HTTP security primitives shared by Registry Stack servers and clients.

mod client;
pub use registry_platform_loopback as loopback;

pub use client::{
    response_trace_id, ProblemDocument, ProblemDocumentError, ResponseTraceError, TraceId,
    TraceIdError,
};

#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
pub use server::*;
