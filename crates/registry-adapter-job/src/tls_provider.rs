// SPDX-License-Identifier: Apache-2.0

//! One process TLS provider for the optional RabbitMQ host and its companion
//! clients. Client construction order must not select a different provider.

/// The process selected an incompatible TLS provider, or the selected provider
/// cannot supply the required FIPS cryptography. This error carries no values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the Adapter job requires its FIPS TLS provider before constructing clients")]
pub struct TlsProviderRefused;

/// Install the reviewed AWS-LC provider before constructing any TLS client.
/// Repeated initialization is safe; an already installed non-FIPS provider
/// refuses instead of silently changing the broker's cryptographic backend.
///
/// # Errors
///
/// The AWS-LC provider is not in FIPS mode, or another client installed an
/// incompatible process provider first.
pub fn initialize() -> Result<(), TlsProviderRefused> {
    let expected = rustls::crypto::aws_lc_rs::default_provider();
    if !expected.fips() {
        return Err(TlsProviderRefused);
    }
    if let Some(installed) = rustls::crypto::CryptoProvider::get_default() {
        return if installed.fips() {
            Ok(())
        } else {
            Err(TlsProviderRefused)
        };
    }
    match expected.install_default() {
        Ok(()) => Ok(()),
        Err(_) => {
            // A concurrent initializer may have won the installation race.
            // Its result must satisfy the same policy before any I/O starts.
            if rustls::crypto::CryptoProvider::get_default().is_some_and(|provider| provider.fips())
            {
                Ok(())
            } else {
                Err(TlsProviderRefused)
            }
        }
    }
}
