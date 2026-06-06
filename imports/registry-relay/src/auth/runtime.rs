// SPDX-License-Identifier: Apache-2.0
//! Runtime authentication provider construction.
//!
//! Startup and governed config apply both use this module so candidate
//! credentials are resolved, commitment-checked, and compiled through the
//! same code path that serves production requests.

use std::collections::HashSet;
use std::sync::Arc;

use registry_platform_authcommon::{
    CredentialCommitmentContext, CredentialFingerprintRefError, CredentialProduct, CredentialType,
};

use crate::config::{self, ApiKeyConfig, Config, OidcConfig};
use crate::error::{ConfigError, Error};

use super::api_key::{ApiKeyAuth, ApiKeyEntry};
use super::middleware::AuthProviderRef;
use super::oidc::{OidcAuth, ReqwestJwksFetcher};
use super::ScopeSet;

/// Build the configured authentication provider.
///
/// The returned provider is immutable. Live governed credential changes build a
/// fresh provider from the candidate config and atomically swap it into the
/// runtime snapshot.
pub async fn build_auth(config: &Config) -> Result<AuthProviderRef, Error> {
    match config.auth.mode {
        config::AuthMode::ApiKey => build_api_key_auth(config),
        config::AuthMode::Oidc => {
            let oidc = config.auth.oidc.as_ref().ok_or_else(|| {
                tracing::error!(
                    code = "config.validation_error",
                    "auth.mode = oidc but no oidc block resolved"
                );
                Error::from(ConfigError::ValidationError)
            })?;
            build_oidc_auth(oidc).await
        }
    }
}

fn build_api_key_auth(config: &Config) -> Result<AuthProviderRef, Error> {
    let mut entries = Vec::with_capacity(config.auth.api_keys.len());
    let mut fingerprints = HashSet::with_capacity(config.auth.api_keys.len());
    for key in &config.auth.api_keys {
        let (entry, fingerprint) = build_api_key_entry(key)?;
        if !fingerprints.insert(fingerprint) {
            tracing::error!(
                code = "config.validation_error",
                api_key_id = %key.id,
                "duplicate API key fingerprint resolved from configured credential references"
            );
            return Err(Error::from(ConfigError::ValidationError));
        }
        entries.push(entry);
    }
    Ok(Arc::new(ApiKeyAuth::new(entries)))
}

/// Build the [`OidcAuth`] provider from its config block.
///
/// Resolves the JWKS URL from `discovery_url` if set; otherwise uses the
/// explicit `jwks_url`. Discovery happens during provider construction so a
/// governed apply can reject an unreachable or invalid candidate before the
/// runtime snapshot is swapped.
async fn build_oidc_auth(oidc: &OidcConfig) -> Result<AuthProviderRef, Error> {
    if oidc.allow_dev_insecure_fetch_urls {
        tracing::warn!(
            code = "oidc.dev_insecure_fetch_urls_enabled",
            "OIDC loopback HTTP issuer, discovery, and JWKS URLs are enabled for local development"
        );
    }

    let fetcher = match (oidc.jwks_url.as_deref(), oidc.discovery_url.as_deref()) {
        (Some(jwks_url), None) => {
            let result = if oidc.allow_dev_insecure_fetch_urls {
                ReqwestJwksFetcher::from_jwks_url_for_dev(jwks_url)
            } else {
                ReqwestJwksFetcher::from_jwks_url(jwks_url)
            };
            result.map_err(|err| {
                tracing::error!(
                    code = "config.validation_error",
                    error = %err,
                    "failed to build OIDC JWKS HTTP client"
                );
                Error::from(ConfigError::ValidationError)
            })?
        }
        (None, Some(discovery_url)) => {
            let result = if oidc.allow_dev_insecure_fetch_urls {
                ReqwestJwksFetcher::from_discovery_url_for_dev(discovery_url, &oidc.issuer).await
            } else {
                ReqwestJwksFetcher::from_discovery_url(discovery_url, &oidc.issuer).await
            };
            result.map_err(|err| {
                tracing::error!(
                    code = "config.validation_error",
                    error = %err,
                    "failed to resolve OIDC discovery document"
                );
                Error::from(ConfigError::ValidationError)
            })?
        }
        _ => {
            tracing::error!(
                code = "config.validation_error",
                "auth.oidc must declare exactly one of jwks_url or discovery_url"
            );
            return Err(Error::from(ConfigError::ValidationError));
        }
    };
    let jwks_url = fetcher.jwks_url().to_string();
    let provider = OidcAuth::new(oidc, Arc::new(fetcher));
    tracing::info!(
        issuer = %oidc.issuer,
        jwks_url = %jwks_url,
        algorithms = ?oidc.algorithms,
        "oidc auth provider wired"
    );
    Ok(Arc::new(provider))
}

/// Resolve one [`ApiKeyConfig`] into an [`ApiKeyEntry`].
///
/// The fingerprint reference can point at an environment variable or a file.
/// The signed config carries only a commitment; this function resolves the
/// secret, verifies the commitment, then constructs the in-memory provider
/// entry without retaining raw credential material.
fn build_api_key_entry(key: &ApiKeyConfig) -> Result<(ApiKeyEntry, String), Error> {
    let context = CredentialCommitmentContext {
        product: CredentialProduct::RegistryRelay,
        credential_type: CredentialType::ApiKey,
        credential_id: &key.id,
    };
    let fingerprint = key
        .fingerprint
        .resolve(context)
        .map_err(|error| match error {
            CredentialFingerprintRefError::MissingSecret => {
                tracing::error!(
                    code = "config.missing_secret",
                    api_key_id = %key.id,
                    "configured API key fingerprint secret is not set at auth build time"
                );
                Error::from(ConfigError::MissingSecret)
            }
            CredentialFingerprintRefError::CommitmentMismatch => {
                tracing::error!(
                    code = "config.validation_error",
                    api_key_id = %key.id,
                    "configured API key fingerprint does not match its signed commitment"
                );
                Error::from(ConfigError::ValidationError)
            }
            other => {
                tracing::error!(
                    code = "config.validation_error",
                    api_key_id = %key.id,
                    reason = ?other,
                    "configured API key fingerprint reference is invalid"
                );
                Error::from(ConfigError::ValidationError)
            }
        })?;
    let scopes: ScopeSet = key.scopes.iter().cloned().collect();
    let entry =
        ApiKeyEntry::new(key.id.clone(), scopes, fingerprint.clone()).map_err(|reason| {
            tracing::error!(
                code = "config.validation_error",
                api_key_id = %key.id,
                reason = %reason,
                "failed to construct API key auth entry from configured fingerprint reference"
            );
            Error::from(ConfigError::ValidationError)
        })?;
    Ok((entry, fingerprint))
}
