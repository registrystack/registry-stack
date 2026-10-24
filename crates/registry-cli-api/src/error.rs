// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// A value-free failure from shared API tooling.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApiError {
    #[error("{0}")]
    Usage(String),
    #[error("the API connection is not configured: {0}")]
    Configuration(String),
    #[error(
        "the API credential is unavailable or unusable; check its saved secret reference, owner-only file permissions (0400 or 0600), or environment variable, then try again"
    )]
    Credential,
    #[error("the API connection could not be established")]
    Connect,
    #[error("the API request timed out")]
    Timeout,
    #[error("the API exchange did not complete")]
    Exchange,
    #[error("the API response exceeded the 8 MiB limit")]
    ResponseTooLarge,
    #[error("the API answered with HTTP status {0}")]
    HttpStatus(u16),
    #[error("the local API tooling could not read or write its file")]
    Io,
}

impl ApiError {
    /// Stable process exit status for a CLI adapter.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::HttpStatus(_) => 1,
            Self::Configuration(_)
            | Self::Credential
            | Self::Connect
            | Self::Timeout
            | Self::Exchange
            | Self::ResponseTooLarge
            | Self::Io => 3,
        }
    }
}
