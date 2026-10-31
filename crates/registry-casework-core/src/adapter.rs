// SPDX-License-Identifier: Apache-2.0
//! Purpose-bound, read-only source context. Providers never discover work or execute actions.

use crate::{EphemeralCredential, ReviewContextContract};
use async_trait::async_trait;
use registry_review_protocol::{PolicyBinding, SubjectBinding};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

/// Every observation identifies exactly the frozen subject and producer contract read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewContextIdentity {
    pub subject: SubjectBinding,
    pub contract: ReviewContextContract,
}

/// The caller's bearer is borrowed for this read and cannot become a stored credential.
#[derive(Debug)]
pub struct HumanDisplayRequest<'a> {
    pub identity: &'a ReviewContextIdentity,
    pub source_profile_id: &'a str,
    pub credential: EphemeralCredential<'a>,
}

/// A delegated staff read carries the already verified Casework credential to
/// a provider that owns a separate, per-call source authorization decision.
/// It is deliberately distinct from [`HumanDisplayRequest`]: a provider must
/// never forward this bearer as though it were a direct human session.
pub struct DelegatedDisplayRequest<'a> {
    pub identity: &'a ReviewContextIdentity,
    pub source_profile_id: &'a str,
    pub credential: EphemeralCredential<'a>,
    pub credential_context: &'a DelegatedCredentialContext,
}

/// Verified subject-token metadata needed by a provider's independent token
/// exchange. The values come from Casework's verifier, never from request
/// headers, and deliberately omit the delegated actor and source authority.
#[derive(Clone, Eq, PartialEq)]
pub struct DelegatedCredentialContext {
    issuer: String,
    subject: String,
    audience: String,
    expires_at: i64,
}

impl DelegatedCredentialContext {
    #[must_use]
    pub fn verified(issuer: String, subject: String, audience: String, expires_at: i64) -> Self {
        Self {
            issuer,
            subject,
            audience,
            expires_at,
        }
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

impl std::fmt::Debug for DelegatedCredentialContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedCredentialContext")
            .field("issuer", &"<verified>")
            .field("subject", &"<redacted>")
            .field("audience", &"<verified>")
            .field("expires_at", &"<verified>")
            .finish()
    }
}

impl std::fmt::Debug for DelegatedDisplayRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedDisplayRequest")
            .field("identity", &"<redacted>")
            .field("source_profile_id", &"<redacted>")
            .field("credential", &self.credential)
            .field("credential_context", &self.credential_context)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanDisplayObservation {
    pub identity: ReviewContextIdentity,
    pub reviewable: bool,
    pub display_reference: Option<String>,
    pub fields: BTreeMap<String, Value>,
}

/// Status deliberately contains no business fields or display reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceStatusObservation {
    pub identity: ReviewContextIdentity,
    pub reviewable: bool,
}

/// A service projection is bound to one pinned task and one compiled purpose.
/// Requested fields come from the compiled policy, never from an HTTP caller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceContextRequest {
    pub identity: ReviewContextIdentity,
    pub request_id: uuid::Uuid,
    pub task_id: uuid::Uuid,
    pub task_revision: i64,
    pub policy: PolicyBinding,
    pub purpose: String,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceContextObservation {
    pub request: ServiceContextRequest,
    pub reviewable: bool,
    pub fields: BTreeMap<String, Value>,
}

impl ServiceContextObservation {
    /// Reject substitution, extra fields, duplicate selections, and partial projections.
    pub fn check(&self, expected: &ServiceContextRequest) -> Result<(), ReviewContextError> {
        if &self.request != expected
            || expected.task_revision < 1
            || expected.purpose.is_empty()
            || expected.fields.is_empty()
            || expected.fields.len() > 128
            || self.fields.len() != expected.fields.len()
            || expected
                .fields
                .iter()
                .any(|field| !self.fields.contains_key(field))
        {
            return Err(ReviewContextError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReviewContextError {
    #[error("the subject is not visible")]
    Concealed,
    #[error("the context provider refused this read")]
    Denied,
    #[error("the context provider is temporarily unavailable")]
    Unavailable,
    #[error("the subject binding is no longer current")]
    BindingMoved,
    #[error("the context contract changed")]
    ContractChanged,
    #[error("the context provider does not support the required capability")]
    Unsupported,
    #[error("the source version differs from Casework; deploy matching Registry Stack versions")]
    VersionMismatch,
    #[error("the source version is unavailable; deploy matching Registry Stack versions")]
    VersionUnavailable,
    #[error("the context provider response is invalid")]
    Invalid,
}

/// Independent capabilities. A status/service credential cannot authorize human display.
#[async_trait]
pub trait ReviewContextProvider: Send + Sync {
    fn provider_id(&self) -> &str;
    fn capabilities(&self) -> &[crate::ReviewContextCapability];
    async fn human_display(
        &self,
        request: HumanDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError>;
    /// A bounded page read with the original caller's borrowed credential.
    /// Results have the same order and cardinality as identities. Providers may
    /// combine transport work; the default preserves scalar-provider behavior.
    async fn human_display_batch(
        &self,
        identities: &[ReviewContextIdentity],
        source_profile_id: &str,
        credential: EphemeralCredential<'_>,
    ) -> Vec<Result<HumanDisplayObservation, ReviewContextError>> {
        if identities.len() > 100 {
            return vec![Err(ReviewContextError::Invalid); identities.len()];
        }
        let credential = credential.expose();
        let mut results = Vec::with_capacity(identities.len());
        for identity in identities {
            results.push(
                self.human_display(HumanDisplayRequest {
                    identity,
                    source_profile_id,
                    credential: EphemeralCredential::new(credential),
                })
                .await,
            );
        }
        results
    }
    /// A delegated staff projection. The shared observation type describes
    /// source data, not human approval or which credential authorized it.
    /// Providers opt in explicitly and acquire
    /// any source credential under their own resource and policy boundary.
    async fn delegated_display(
        &self,
        _request: DelegatedDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        Err(ReviewContextError::Denied)
    }
    /// A bounded delegated projection preserving input order and cardinality.
    /// The default refuses every item and never falls back to human display.
    async fn delegated_display_batch(
        &self,
        identities: &[ReviewContextIdentity],
        _source_profile_id: &str,
        _credential: EphemeralCredential<'_>,
        _credential_context: &DelegatedCredentialContext,
    ) -> Vec<Result<HumanDisplayObservation, ReviewContextError>> {
        if identities.len() > 100 {
            return vec![Err(ReviewContextError::Invalid); identities.len()];
        }
        vec![Err(ReviewContextError::Denied); identities.len()]
    }
    async fn service_status(
        &self,
        identity: &ReviewContextIdentity,
    ) -> Result<ServiceStatusObservation, ReviewContextError>;
    async fn task_grant_context(
        &self,
        _request: &ServiceContextRequest,
    ) -> Result<ServiceContextObservation, ReviewContextError> {
        Err(ReviewContextError::Unsupported)
    }
    /// Called only at task/stage creation. The runtime retains derived staffing metadata.
    async fn routing_context(
        &self,
        _request: &ServiceContextRequest,
    ) -> Result<ServiceContextObservation, ReviewContextError> {
        Err(ReviewContextError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RefusingProvider;

    #[async_trait]
    impl ReviewContextProvider for RefusingProvider {
        fn provider_id(&self) -> &str {
            "refusing"
        }

        fn capabilities(&self) -> &[crate::ReviewContextCapability] {
            &[]
        }

        async fn human_display(
            &self,
            _request: HumanDisplayRequest<'_>,
        ) -> Result<HumanDisplayObservation, ReviewContextError> {
            Err(ReviewContextError::Denied)
        }

        async fn service_status(
            &self,
            _identity: &ReviewContextIdentity,
        ) -> Result<ServiceStatusObservation, ReviewContextError> {
            Err(ReviewContextError::Denied)
        }
    }

    #[test]
    fn service_projection_refuses_widening_or_task_substitution() {
        let digest =
            registry_review_protocol::ContentDigest::parse(&format!("sha256:{}", "a".repeat(64)))
                .unwrap();
        let request = ServiceContextRequest {
            identity: ReviewContextIdentity {
                subject: SubjectBinding {
                    source: "source".into(),
                    subject_type: "proposal".into(),
                    id: "id".into(),
                    version: "1".into(),
                    digest: digest.clone(),
                },
                contract: ReviewContextContract {
                    id: "urn:context".into(),
                    revision: digest.clone(),
                    schema_digest: digest.clone(),
                },
            },
            request_id: uuid::Uuid::new_v4(),
            task_id: uuid::Uuid::new_v4(),
            task_revision: 1,
            policy: PolicyBinding {
                id: "policy".into(),
                version: "1".into(),
                digest,
            },
            purpose: "routing".into(),
            fields: vec!["region".into()],
        };
        let mut observation = ServiceContextObservation {
            request: request.clone(),
            reviewable: true,
            fields: BTreeMap::from([("region".into(), Value::String("north".into()))]),
        };
        assert_eq!(observation.check(&request), Ok(()));
        observation
            .fields
            .insert("private".into(), Value::Bool(true));
        assert_eq!(
            observation.check(&request),
            Err(ReviewContextError::Invalid)
        );
        observation.fields.remove("private");
        observation.request.task_revision += 1;
        assert_eq!(
            observation.check(&request),
            Err(ReviewContextError::Invalid)
        );
    }

    #[test]
    fn delegated_display_is_a_distinct_default_denial() {
        let digest =
            registry_review_protocol::ContentDigest::parse(&format!("sha256:{}", "a".repeat(64)))
                .unwrap();
        let identity = ReviewContextIdentity {
            subject: SubjectBinding {
                source: "source".into(),
                subject_type: "proposal".into(),
                id: "id".into(),
                version: "1".into(),
                digest: digest.clone(),
            },
            contract: ReviewContextContract {
                id: "urn:context".into(),
                revision: digest.clone(),
                schema_digest: digest,
            },
        };
        let provider = RefusingProvider;
        let context = DelegatedCredentialContext::verified(
            "https://casework.test".into(),
            "officer-7".into(),
            "urn:casework".into(),
            1,
        );
        assert_eq!(
            run_ready(provider.delegated_display(DelegatedDisplayRequest {
                identity: &identity,
                source_profile_id: "delegated-review",
                credential: EphemeralCredential::new("opaque"),
                credential_context: &context,
            })),
            Err(ReviewContextError::Denied)
        );
        assert_eq!(
            run_ready(provider.delegated_display_batch(
                std::slice::from_ref(&identity),
                "delegated-review",
                EphemeralCredential::new("opaque"),
                &context,
            )),
            vec![Err(ReviewContextError::Denied)]
        );
    }

    fn run_ready<T>(future: impl std::future::Future<Output = T>) -> T {
        struct Noop;
        impl std::task::Wake for Noop {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = std::task::Waker::from(std::sync::Arc::new(Noop));
        let mut context = std::task::Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("the default refusal must be immediately ready"),
        }
    }
}
