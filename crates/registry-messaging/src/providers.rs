// SPDX-License-Identifier: Apache-2.0

//! Provider activation: the runtime half of each configured provider joined
//! with its package half, at startup, into the transport the dispatch worker
//! sends through and, for an `http` provider declaring `receipts: callback`,
//! the receiver its delivery callbacks are verified and read with.
//!
//! Activation resolves every credential, trust bundle, and callback verifier
//! secret before either listener binds. A provider that cannot be activated
//! stops the runtime with an error naming the provider and the member, never
//! a secret value. A package provider the runtime configuration gives no
//! connection is not activated: startup logs it, and its messages fail with
//! `provider-unconfigured`.
//!
//! The adapters map each provider kind's classified attempt onto the
//! dispatch core's [`SendOutcome`]. The value-free attempt detail stays in the
//! provider's own debug log.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use registry_messaging_core::{
    CallbackBodyEncoding, CallbackVerifierConfig, ResolvedCallbackVerifier, SenderProfile,
    UncertainPolicy,
};
use registry_platform_config::{ProtectedSecret, SecretResolver};
use registry_platform_dispatch::SendOutcome;
use thiserror::Error;

use crate::config::{describe_secret_failure, ProviderConnection, RuntimeConfig};
use crate::dispatch::{MessageTransport, OutboundMessage, Transports, MINIMUM_ATTEMPT_TIMEOUT};
use crate::http_provider::{HttpProvider, HttpProviderMessage};
use crate::package::LoadedPackage;
use crate::smtp::{SmtpMessage, SmtpProvider};

/// Why a configured provider could not be activated. The reason names the
/// member or secret reference, never a secret value.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("provider {provider} could not be activated: {reason}")]
pub struct ProviderActivationError {
    pub provider: String,
    pub reason: String,
}

/// The callback receivers of the activated providers, by provider id.
pub type CallbackReceivers = BTreeMap<String, Arc<CallbackReceiver>>;

/// Activate every provider `config` gives a connection, registering its
/// transport in `transports`, and return the callback receivers.
///
/// # Errors
///
/// [`ProviderActivationError`] for the first provider whose settings,
/// credentials, trust bundle, scripts, or callback verifier secret cannot be
/// used, or that already has a registered transport.
pub fn activate_providers(
    config: &RuntimeConfig,
    loaded: &LoadedPackage,
    secrets: &SecretResolver,
    transports: &mut Transports,
) -> Result<CallbackReceivers, ProviderActivationError> {
    let mut receivers = CallbackReceivers::new();
    for (id, connection) in &config.providers {
        let refused = |reason: String| ProviderActivationError {
            provider: id.clone(),
            reason,
        };
        let transport: Arc<dyn MessageTransport> = match connection {
            ProviderConnection::Smtp(settings) => Arc::new(SmtpTransport(
                settings
                    .activate(secrets)
                    .map_err(|error| refused(error.to_string()))?,
            )),
            ProviderConnection::Http(settings) => {
                let source = loaded.providers.get(id).ok_or_else(|| {
                    refused("the package ships no providers/<id>/provider.yaml".to_owned())
                })?;
                let trust = match &settings.tls_trust_profile {
                    None => None,
                    Some(name) => {
                        let profile = config.tls_trust_profiles.get(name).ok_or_else(|| {
                            refused(
                                "tlsTrustProfile names a profile tlsTrustProfiles does not \
                                 declare"
                                    .to_owned(),
                            )
                        })?;
                        Some(resolve(secrets, "bundleRef", &profile.bundle_ref).map_err(
                            |reason| refused(format!("tlsTrustProfiles.{name}: {reason}")),
                        )?)
                    }
                };
                let provider = Arc::new(
                    settings
                        .activate(
                            id,
                            &source.package,
                            source.scripts(),
                            trust.as_ref().map(ProtectedSecret::expose_secret),
                            secrets,
                        )
                        .map_err(|error| refused(error.to_string()))?,
                );
                if let Some(verifier) = &settings.callback_verifier {
                    let verifier =
                        CallbackVerifierSecret::resolve(verifier, secrets).map_err(refused)?;
                    receivers.insert(
                        id.clone(),
                        Arc::new(CallbackReceiver {
                            provider: Arc::clone(&provider),
                            verifier,
                        }),
                    );
                }
                let idempotent_submit = loaded
                    .package
                    .provider(id)
                    .is_some_and(|declared| declared.idempotent_submit);
                let maximum_segments = loaded
                    .package
                    .sender_profiles()
                    .filter(|profile| profile.provider == *id)
                    .map(|profile| (profile.id.clone(), profile.maximum_segments))
                    .collect();
                Arc::new(HttpTransport {
                    provider,
                    idempotent_submit,
                    maximum_segments,
                })
            }
        };
        transports
            .insert(id.clone(), transport)
            .map_err(|error| refused(error.to_string()))?;
    }
    for declared in loaded.package.providers() {
        if transports.get(&declared.id).is_none() {
            tracing::warn!(
                provider = declared.id.as_str(),
                "the runtime configuration gives this provider no connection; its messages \
                 fail with provider-unconfigured"
            );
        }
    }
    Ok(receivers)
}

fn resolve(
    secrets: &SecretResolver,
    field: &'static str,
    reference: &str,
) -> Result<ProtectedSecret, String> {
    secrets
        .resolve(reference)
        .map_err(|error| describe_secret_failure(field, reference, &error))
}

/// One `http` provider's delivery callback: the verifier with its secret
/// resolved, and the provider whose receipt script reads a verified callback.
pub struct CallbackReceiver {
    provider: Arc<HttpProvider>,
    verifier: CallbackVerifierSecret,
}

impl fmt::Debug for CallbackReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallbackReceiver")
            .field("provider", &self.provider)
            .field("verifier", &self.verifier.kind())
            .finish()
    }
}

impl CallbackReceiver {
    /// The verifier, over the resolved secret.
    #[must_use]
    pub fn verifier(&self) -> ResolvedCallbackVerifier<'_> {
        match &self.verifier {
            CallbackVerifierSecret::HmacSha1UrlForm { header, secret } => {
                ResolvedCallbackVerifier::HmacSha1UrlForm {
                    header,
                    secret: secret.expose_secret(),
                }
            }
            CallbackVerifierSecret::HmacSha256Body {
                header,
                encoding,
                secret,
            } => ResolvedCallbackVerifier::HmacSha256Body {
                header,
                encoding: *encoding,
                secret: secret.expose_secret(),
            },
            CallbackVerifierSecret::PathToken { token } => ResolvedCallbackVerifier::PathToken {
                token: token.expose_secret(),
            },
        }
    }

    /// The provider whose receipt script reads a verified callback.
    #[must_use]
    pub fn provider(&self) -> &HttpProvider {
        &self.provider
    }
}

enum CallbackVerifierSecret {
    HmacSha1UrlForm {
        header: String,
        secret: ProtectedSecret,
    },
    HmacSha256Body {
        header: String,
        encoding: CallbackBodyEncoding,
        secret: ProtectedSecret,
    },
    PathToken {
        token: ProtectedSecret,
    },
}

impl CallbackVerifierSecret {
    fn resolve(config: &CallbackVerifierConfig, secrets: &SecretResolver) -> Result<Self, String> {
        let field = |reason: String| format!("callbackVerifier: {reason}");
        Ok(match config {
            CallbackVerifierConfig::HmacSha1UrlForm { header, secret_ref } => {
                Self::HmacSha1UrlForm {
                    header: header.clone(),
                    secret: resolve(secrets, "callbackVerifier.secretRef", secret_ref)
                        .map_err(field)?,
                }
            }
            CallbackVerifierConfig::HmacSha256Body {
                header,
                encoding,
                secret_ref,
            } => Self::HmacSha256Body {
                header: header.clone(),
                encoding: *encoding,
                secret: resolve(secrets, "callbackVerifier.secretRef", secret_ref)
                    .map_err(field)?,
            },
            CallbackVerifierConfig::PathToken { token_ref } => Self::PathToken {
                token: resolve(secrets, "callbackVerifier.tokenRef", token_ref).map_err(field)?,
            },
        })
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::HmacSha1UrlForm { .. } => "hmac-sha1-url-form",
            Self::HmacSha256Body { .. } => "hmac-sha256-body",
            Self::PathToken { .. } => "path-token",
        }
    }
}

/// An SMTP provider as a dispatch transport.
struct SmtpTransport(SmtpProvider);

#[async_trait]
impl MessageTransport for SmtpTransport {
    fn attempt_timeout(&self) -> Duration {
        self.0.attempt_timeout()
    }

    async fn send(&self, message: &OutboundMessage) -> SendOutcome {
        let message_id = message.message_id.to_string();
        self.0
            .send(&SmtpMessage {
                message_id: &message_id,
                from: &message.sender,
                to: &message.recipient,
                parts: &message.parts,
            })
            .await
            .outcome
    }
}

/// An HTTP provider as a dispatch transport.
struct HttpTransport {
    provider: Arc<HttpProvider>,
    /// Whether the package declares `idempotentSubmit`, the one condition
    /// under which the prepare script sees the idempotency key.
    idempotent_submit: bool,
    /// The SMS segment bound of each sender profile routed through this
    /// provider, by profile id.
    maximum_segments: BTreeMap<String, Option<u8>>,
}

#[async_trait]
impl MessageTransport for HttpTransport {
    /// The provider's own timeout covers the whole send; the dispatch seam
    /// counts in whole seconds from one, so a shorter timeout is given one.
    fn attempt_timeout(&self) -> Duration {
        self.provider.timeout().max(MINIMUM_ATTEMPT_TIMEOUT)
    }

    async fn send(&self, message: &OutboundMessage) -> SendOutcome {
        // The profile as the message was accepted with: its channel, provider,
        // and sender are the persisted ones, so a later package never changes
        // what a retry sends.
        let profile = SenderProfile {
            id: message.sender_profile.clone(),
            channel: message.channel,
            provider: message.provider.clone(),
            sender: message.sender.clone(),
            maximum_segments: self
                .maximum_segments
                .get(&message.sender_profile)
                .copied()
                .flatten(),
            retry: None,
            on_uncertain: UncertainPolicy::default(),
            accept_duplicates: false,
            default_expiry_seconds: None,
        };
        let message_id = message.message_id.to_string();
        self.provider
            .send(&HttpProviderMessage {
                message_id: &message_id,
                attempt: message.attempt,
                generation: message.generation,
                channel: message.channel,
                profile: &profile,
                recipient: &message.recipient,
                parts: &message.parts,
                idempotency_key: self
                    .idempotent_submit
                    .then_some(message.idempotency_key.as_str()),
            })
            .await
            .outcome
    }
}

#[cfg(test)]
mod tests;
