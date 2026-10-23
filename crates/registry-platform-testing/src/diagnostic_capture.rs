// SPDX-License-Identifier: Apache-2.0
//! In-memory capture and malformed credentials for authentication diagnostics tests.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{
    io::Write,
    sync::{Arc, Mutex},
};

/// Shared in-memory writer for scoped, value-free diagnostic assertions.
#[derive(Clone, Debug, Default)]
pub struct CapturedDiagnosticLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedDiagnosticLogs {
    /// Return a UTF-8 snapshot after the observed operation completes.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("diagnostic capture lock").clone())
            .expect("diagnostics are UTF-8")
    }
}

impl Write for CapturedDiagnosticLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("diagnostic capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Empty, oversized, malformed-base64 and duplicate-member credentials.
#[must_use]
pub fn malformed_access_token_fixtures() -> Vec<String> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
    let duplicate_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","alg":"ES256"}"#);
    let duplicate_claims = URL_SAFE_NO_PAD.encode(br#"{"sub":"canary-one","sub":"canary-two"}"#);
    vec![
        String::new(),
        "canary-sensitive-token".repeat(8192),
        "!canary-invalid-base64.e30.c2ln".to_owned(),
        format!("{duplicate_header}.e30.c2ln"),
        format!("{header}.{duplicate_claims}.c2ln"),
    ]
}
