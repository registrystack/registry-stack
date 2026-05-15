// SPDX-License-Identifier: Apache-2.0
//! Syslog audit sink over a local Unix datagram socket.

use std::path::{Path, PathBuf};

use super::{AuditEnvelope, AuditError, AuditFuture, AuditSink};

/// Sends audit JSONL records to a local syslog Unix datagram socket.
#[derive(Debug, Clone)]
pub struct SyslogSink {
    socket_path: PathBuf,
}

impl SyslogSink {
    /// Construct a sink using the platform's common local syslog socket.
    #[must_use]
    pub fn new() -> Self {
        Self::with_socket_path(default_socket_path())
    }

    /// Construct a sink with an explicit socket path. Intended for
    /// tests and non-standard syslog deployments.
    #[must_use]
    pub fn with_socket_path(path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: path.into(),
        }
    }
}

impl Default for SyslogSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for SyslogSink {
    fn write<'a>(&'a self, envelope: AuditEnvelope) -> AuditFuture<'a> {
        Box::pin(async move {
            let line = envelope.to_jsonl()?;
            send_datagram(&self.socket_path, line.as_bytes()).await
        })
    }

    fn flush<'a>(&'a self) -> AuditFuture<'a> {
        Box::pin(async move { Ok(()) })
    }
}

#[cfg(unix)]
async fn send_datagram(socket_path: &Path, bytes: &[u8]) -> Result<(), AuditError> {
    let socket = tokio::net::UnixDatagram::unbound().map_err(AuditError::Io)?;
    socket
        .send_to(bytes, socket_path)
        .await
        .map_err(AuditError::Io)?;
    Ok(())
}

#[cfg(not(unix))]
async fn send_datagram(_socket_path: &Path, _bytes: &[u8]) -> Result<(), AuditError> {
    Err(AuditError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "syslog audit sink requires Unix datagram sockets",
    )))
}

#[cfg(target_os = "macos")]
fn default_socket_path() -> PathBuf {
    PathBuf::from("/var/run/syslog")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_socket_path() -> PathBuf {
    PathBuf::from("/dev/log")
}

#[cfg(not(unix))]
fn default_socket_path() -> PathBuf {
    PathBuf::from("")
}
