//! The warning for an expired client identifier certificate, in a test binary
//! of its own under the process-wide log subscriber.
//!
//! A thread-scoped subscriber cannot capture it reliably. `tracing` caches a
//! callsite's interest the first time any thread reaches it, and while a
//! single dispatcher is registered it asks only that thread's subscriber. A
//! parallel test with no subscriber that reaches the warning first disables it
//! for every thread, and nothing is captured. The process-wide subscriber is
//! the one every thread asks. It also hears every thread, so no other test in
//! this binary may reach the warning, or the count below would include it.

mod common;

use std::sync::atomic::Ordering;

use common::{Harness, Options, HOST};

/// Unix seconds of 2091-01-01, after the harness certificate's `notAfter`.
const AFTER_CERTIFICATE_EXPIRY: u64 = 3_818_448_000;

#[derive(Clone, Default)]
struct LogBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn certificate_expiry_logs_one_warning_without_certificate_content() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;
    let logs = LogBuffer::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish(),
    )
    .expect("this binary installs one log subscriber");
    server.get("/ready").await.assert_status_ok();
    harness
        .time
        .store(AFTER_CERTIFICATE_EXPIRY, Ordering::SeqCst);
    for _ in 0..3 {
        server
            .get("/ready")
            .await
            .assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.matches("WARN").count(), 1, "{text}");
    assert!(text.contains("certificate"), "{text}");
    assert!(!text.contains(HOST), "{text}");
    assert!(!text.contains("BEGIN CERTIFICATE"), "{text}");
}
