// SPDX-License-Identifier: Apache-2.0
//! Read-only native Proposal context provider. No discovery, events or source writes.
mod config;
use async_trait::async_trait;
pub use config::*;
use registry_breg_client::{
    BRegProposalReviewDocument, BaseRegistryClient, BaseRegistryClientError, BearerToken,
};
use registry_casework_core::*;

pub struct BregContextProvider {
    id: String,
    export: BregContextExport,
    client: BaseRegistryClient,
    status_profile: String,
}
impl BregContextProvider {
    pub fn new(
        id: String,
        export: BregContextExport,
        client: BaseRegistryClient,
        status_profile: String,
    ) -> Result<Self, ReviewContextError> {
        export.check()?;
        if id.is_empty() || status_profile.is_empty() {
            return Err(ReviewContextError::Invalid);
        }
        Ok(Self {
            id,
            export,
            client,
            status_profile,
        })
    }
    async fn read(
        &self,
        client: &BaseRegistryClient,
        identity: &ReviewContextIdentity,
        profile: &str,
        display: bool,
    ) -> Result<BRegProposalReviewDocument, ReviewContextError> {
        if identity.contract != self.export.contract
            || identity.subject.source != self.export.source_namespace
            || identity.subject.subject_type != "proposal"
        {
            return Err(ReviewContextError::ContractChanged);
        }
        let metadata = client
            .registry_contract(Some(profile))
            .await
            .map_err(map_error)?
            .value;
        // The exported schema is covered by this exact compiled Registry revision.
        // A metadata change refuses before a business-value read.
        if metadata.registry_revision() != self.export.registry_revision {
            return Err(ReviewContextError::ContractChanged);
        }
        let binding = if display {
            metadata.select_proposal_review_context(profile, &self.export.action_id)
        } else {
            metadata.select_proposal_review_status(profile, &self.export.action_id)
        }
        .map_err(|_| ReviewContextError::Concealed)?;
        let document = client
            .read_proposal_review_by_id(&binding, &identity.subject.id)
            .await
            .map_err(|error| match error {
                // A context reply without the owning closed contract is not
                // the interface this paired provider was authorized to use.
                BaseRegistryClientError::InvalidRequest { .. } if display => {
                    ReviewContextError::ContractChanged
                }
                error => map_error(error),
            })?
            .value;
        if document.subject.source != identity.subject.source
            || document.subject.subject_type != identity.subject.subject_type
            || document.subject.id != identity.subject.id
            || document.subject.version != identity.subject.version
            || document.subject.digest != identity.subject.digest.as_str()
        {
            return Err(ReviewContextError::BindingMoved);
        }
        if !document.context.contract.as_ref().is_some_and(|contract| {
            contract.id == self.export.contract.id
                && contract.revision == self.export.contract.revision.as_str()
                && contract.schema_digest == self.export.contract.schema_digest.as_str()
        }) {
            return Err(ReviewContextError::ContractChanged);
        }
        if client
            .registry_contract(Some(profile))
            .await
            .map_err(map_error)?
            .value
            .registry_revision()
            != self.export.registry_revision
        {
            return Err(ReviewContextError::ContractChanged);
        }
        Ok(document)
    }
}
#[async_trait]
impl ReviewContextProvider for BregContextProvider {
    fn provider_id(&self) -> &str {
        &self.id
    }
    fn capabilities(&self) -> &[ReviewContextCapability] {
        &[
            ReviewContextCapability::HumanDisplay,
            ReviewContextCapability::ServiceStatus,
        ]
    }
    async fn human_display(
        &self,
        request: HumanDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        // Override every configured service token for this one exact human read.
        let token = BearerToken::new(request.credential.expose().to_owned())
            .map_err(|_| ReviewContextError::Denied)?;
        let client = self.client.with_bearer_token(token);
        let document = self
            .read(&client, request.identity, request.source_profile_id, true)
            .await?;
        let fields = document.context.fields.ok_or(ReviewContextError::Invalid)?;
        let schema = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&self.export.schema)
            .map_err(|_| ReviewContextError::Invalid)?;
        if !schema
            .is_valid(&serde_json::to_value(&fields).map_err(|_| ReviewContextError::Invalid)?)
        {
            return Err(ReviewContextError::Invalid);
        }
        let display_reference = Some(document.context.reference);
        Ok(HumanDisplayObservation {
            identity: request.identity.clone(),
            reviewable: document.reviewable,
            display_reference,
            fields,
        })
    }
    async fn service_status(
        &self,
        identity: &ReviewContextIdentity,
    ) -> Result<ServiceStatusObservation, ReviewContextError> {
        let document = self
            .read(&self.client, identity, &self.status_profile, false)
            .await?;
        // A status credential is never used for a display or field projection.
        if document.context.fields.is_some() {
            return Err(ReviewContextError::Invalid);
        }
        Ok(ServiceStatusObservation {
            identity: identity.clone(),
            reviewable: document.reviewable,
        })
    }
}
fn map_error(error: BaseRegistryClientError) -> ReviewContextError {
    match error {
        BaseRegistryClientError::Problem {
            status: 401 | 403 | 404,
            ..
        }
        | BaseRegistryClientError::UnrecognizedProblem {
            status: 401 | 403 | 404,
            ..
        } => ReviewContextError::Concealed,
        BaseRegistryClientError::Transport { .. } | BaseRegistryClientError::Token(_) => {
            ReviewContextError::Unavailable
        }
        BaseRegistryClientError::Problem {
            status: 409 | 412, ..
        } => ReviewContextError::BindingMoved,
        BaseRegistryClientError::Problem {
            status: 500..=599, ..
        }
        | BaseRegistryClientError::UnrecognizedProblem {
            status: 500..=599, ..
        } => ReviewContextError::Unavailable,
        _ => ReviewContextError::Invalid,
    }
}
