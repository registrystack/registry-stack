// SPDX-License-Identifier: Apache-2.0

//! The gateway's minimized tool-call audit.
//!
//! The shared writer accepts a request entry before dispatch and a response
//! entry before the result is released. Its request handle writes an
//! `unfinished` response if the call is cancelled or unwinds.

use registry_platform_audit::{AuditRequest, AuditUnavailable, AuditWriter};
use serde_json::{json, Value};

const AUDIT_SCHEMA: &str = "registry-breg-mcp.tool-call/v1";

/// Value-free facts shared by the request and response entries of one call.
pub(crate) struct ToolAudit<'a> {
    pub(crate) tool: &'a str,
    pub(crate) principal_pseudonym: &'a str,
    pub(crate) client_pseudonym: &'a str,
}

impl ToolAudit<'_> {
    fn record(&self) -> Value {
        json!({
            "event": "breg_mcp.tool_call",
            "tool": self.tool,
            "principalPseudonym": self.principal_pseudonym,
            "clientPseudonym": self.client_pseudonym,
        })
    }

    pub(crate) fn response(&self, outcome: &str, reason: Option<&str>) -> Value {
        let mut record = self.record();
        record["outcome"] = Value::String(outcome.to_owned());
        if let Some(reason) = reason {
            record["reason"] = Value::String(reason.to_owned());
        }
        record
    }

    fn unfinished(&self) -> Value {
        self.response("unfinished", None)
    }
}

/// The process-lifetime writer for tool calls.
pub(crate) struct ToolAuditLog {
    writer: AuditWriter,
}

impl ToolAuditLog {
    pub(crate) const fn new(writer: AuditWriter) -> Self {
        Self { writer }
    }

    /// Accept the request entry before any exchange or registry dispatch.
    pub(crate) async fn begin(
        &self,
        correlation: String,
        record: &ToolAudit<'_>,
    ) -> Result<AuditRequest, AuditUnavailable> {
        self.writer
            .begin(
                AUDIT_SCHEMA,
                correlation,
                record.record(),
                record.unfinished(),
            )
            .await
    }

    pub(crate) async fn ready(&self) -> bool {
        self.writer.ready().await
    }

    #[cfg(test)]
    pub(crate) fn refusing_after(accepted: usize) -> Self {
        use std::io::{self, Write};
        use std::sync::{Arc, Mutex};

        struct RefusingSink {
            accepted: usize,
            writes: Arc<Mutex<usize>>,
        }

        impl Write for RefusingSink {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let mut writes = self.writes.lock().expect("write count lock");
                if *writes >= self.accepted {
                    return Err(io::Error::other("deliberate audit refusal"));
                }
                *writes += 1;
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        Self::new(AuditWriter::from_line_sink(Box::new(RefusingSink {
            accepted,
            writes: Arc::new(Mutex::new(0)),
        })))
    }

    #[cfg(test)]
    pub(crate) fn capture() -> (Self, AuditCapture) {
        let buffer = TestBuffer::default();
        let writer = AuditWriter::from_line_sink(Box::new(buffer.clone()));
        (Self::new(writer.clone()), AuditCapture { writer, buffer })
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
struct TestBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(test)]
impl std::io::Write for TestBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) struct AuditCapture {
    writer: AuditWriter,
    buffer: TestBuffer,
}

#[cfg(test)]
impl AuditCapture {
    pub(crate) fn entries(&self) -> Vec<Value> {
        self.writer.wait_for_detached_entries();
        let bytes = self.buffer.0.lock().expect("buffer lock").clone();
        String::from_utf8(bytes)
            .expect("UTF-8 audit")
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit line"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };

    use super::*;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("buffer lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn request_and_response_are_minimized_and_share_correlation() {
        let buffer = Buffer::default();
        let writer = AuditWriter::from_line_sink(Box::new(buffer.clone()));
        let log = ToolAuditLog::new(writer);
        let record = ToolAudit {
            tool: "start_application",
            principal_pseudonym: "principal-pseudonym",
            client_pseudonym: "client-pseudonym",
        };
        let mut request = log
            .begin("correlation-1".to_owned(), &record)
            .await
            .expect("request accepted");
        request
            .respond(record.response("ok", None))
            .await
            .expect("response accepted");

        let text =
            String::from_utf8(buffer.0.lock().expect("buffer lock").clone()).expect("UTF-8 lines");
        let entries: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit line"))
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["schema"], AUDIT_SCHEMA);
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[0]["correlation"], "correlation-1");
        assert_eq!(entries[1]["correlation"], "correlation-1");
        assert_eq!(entries[0]["record"]["outcome"], Value::Null);
        assert_eq!(entries[1]["record"]["outcome"], "ok");
        assert!(!text.contains("requestId"));
    }

    #[tokio::test]
    async fn a_dropped_request_writes_unfinished_with_the_same_correlation() {
        let buffer = Buffer::default();
        let writer = AuditWriter::from_line_sink(Box::new(buffer.clone()));
        let log = ToolAuditLog::new(writer.clone());
        let record = ToolAudit {
            tool: "get_my_details",
            principal_pseudonym: "principal-pseudonym",
            client_pseudonym: "client-pseudonym",
        };
        let request = log
            .begin("correlation-2".to_owned(), &record)
            .await
            .expect("request accepted");
        drop(request);
        writer.wait_for_detached_entries();

        let text =
            String::from_utf8(buffer.0.lock().expect("buffer lock").clone()).expect("UTF-8 lines");
        let entries: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit line"))
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[1]["correlation"], "correlation-2");
        assert_eq!(entries[1]["record"]["outcome"], "unfinished");
    }
}
