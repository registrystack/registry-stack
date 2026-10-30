// SPDX-License-Identifier: Apache-2.0

use registry_platform_audit::{AuditRequest, AuditUnavailable, AuditWriter};
use serde_json::{json, Value};

/// Product wrapper-owned audit identity, allowing compatibility schemas to remain exact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditOptions {
    schema: String,
    event: String,
}

impl AuditOptions {
    pub fn new(
        schema: impl Into<String>,
        event: impl Into<String>,
    ) -> Result<Self, AuditOptionsError> {
        let options = Self {
            schema: schema.into(),
            event: event.into(),
        };
        if !valid_name(&options.schema) || !valid_name(&options.event) {
            return Err(AuditOptionsError);
        }
        Ok(options)
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.is_ascii()
        && !value.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the MCP audit identity is invalid")]
pub struct AuditOptionsError;

impl AuditOptions {
    pub(crate) fn event(&self) -> &str {
        &self.event
    }
}

pub struct ToolAuditLog {
    writer: AuditWriter,
}

impl ToolAuditLog {
    #[must_use]
    pub const fn new(writer: AuditWriter) -> Self {
        Self { writer }
    }

    pub(crate) async fn begin(
        &self,
        correlation: String,
        options: &AuditOptions,
        record: &ToolAudit<'_>,
    ) -> Result<AuditRequest, AuditUnavailable> {
        self.writer
            .begin(
                &options.schema,
                correlation,
                record.request(&options.event),
                record.unfinished(&options.event),
            )
            .await
    }

    pub async fn ready(&self) -> bool {
        self.writer.ready().await
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn refusing_after_for_test(accepted: usize) -> Self {
        use std::{
            io::{self, Write},
            sync::{Arc, Mutex},
        };

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
}

pub(crate) struct ToolAudit<'a> {
    pub(crate) tool: &'a str,
    pub(crate) principal_pseudonym: &'a str,
    pub(crate) client_pseudonym: &'a str,
}

impl ToolAudit<'_> {
    fn request(&self, event: &str) -> Value {
        json!({
            "event": event,
            "tool": self.tool,
            "principalPseudonym": self.principal_pseudonym,
            "clientPseudonym": self.client_pseudonym,
        })
    }

    pub(crate) fn response(&self, event: &str, outcome: &str, reason: Option<&str>) -> Value {
        let mut record = self.request(event);
        record["outcome"] = Value::String(outcome.to_owned());
        if let Some(reason) = reason {
            record["reason"] = Value::String(reason.to_owned());
        }
        record
    }

    fn unfinished(&self, event: &str) -> Value {
        self.response(event, "unfinished", None)
    }
}
