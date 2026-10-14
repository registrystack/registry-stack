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
}
