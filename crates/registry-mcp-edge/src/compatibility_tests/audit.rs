// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

use registry_platform_audit::AuditWriter;
use serde_json::Value;

use crate::audit::{AuditOptions, ToolAudit, ToolAuditLog};

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

fn fixture() -> (ToolAuditLog, AuditWriter, Buffer, AuditOptions) {
    let buffer = Buffer::default();
    let writer = AuditWriter::from_line_sink(Box::new(buffer.clone()));
    (
        ToolAuditLog::new(writer.clone()),
        writer,
        buffer,
        AuditOptions::new("registry-breg-mcp.tool-call/v1", "breg_mcp.tool_call")
            .expect("audit options"),
    )
}

fn entries(buffer: &Buffer) -> Vec<Value> {
    String::from_utf8(buffer.0.lock().expect("buffer lock").clone())
        .expect("UTF-8 audit")
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line"))
        .collect()
}

#[tokio::test]
async fn request_and_response_are_minimized_and_share_correlation() {
    let (audit, _, buffer, options) = fixture();
    let record = ToolAudit {
        tool: "get_my_details",
        principal_pseudonym: "principal-pseudonym",
        client_pseudonym: "client-pseudonym",
    };
    let mut request = audit
        .begin("correlation-a".to_owned(), &options, &record)
        .await
        .expect("request audit");
    request
        .respond(record.response("breg_mcp.tool_call", "ok", None))
        .await
        .expect("response audit");

    let entries = entries(&buffer);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    assert_eq!(entries[0]["record"]["tool"], "get_my_details");
    assert_eq!(
        entries[0]["record"]["principalPseudonym"],
        "principal-pseudonym"
    );
    assert_eq!(entries[0]["record"]["clientPseudonym"], "client-pseudonym");
    assert!(entries[0]["record"].get("outcome").is_none());
    assert_eq!(entries[1]["record"]["outcome"], "ok");
    for forbidden in ["subject-a", "Bearer", "registry-value"] {
        assert!(!buffer_text(&buffer).contains(forbidden));
    }
}

#[tokio::test]
async fn a_dropped_request_writes_unfinished_with_the_same_correlation() {
    let (audit, writer, buffer, options) = fixture();
    let record = ToolAudit {
        tool: "update_application",
        principal_pseudonym: "principal-pseudonym",
        client_pseudonym: "client-pseudonym",
    };
    let request = audit
        .begin("correlation-b".to_owned(), &options, &record)
        .await
        .expect("request audit");
    drop(request);
    writer.wait_for_detached_entries();

    let entries = entries(&buffer);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    assert_eq!(entries[1]["record"]["outcome"], "unfinished");
    assert!(entries[1]["record"].get("reason").is_none());
}

fn buffer_text(buffer: &Buffer) -> String {
    String::from_utf8(buffer.0.lock().expect("buffer lock").clone()).expect("UTF-8 audit")
}
