// SPDX-License-Identifier: Apache-2.0
//! Binding-safe JSON facade over the typed client.

use registry_notary_core::{
    BatchEvaluateRequest, CredentialIssueRequest, EvaluateRequest, RenderRequest,
};

use crate::{PortableClientError, RegistryNotaryClient, RequestOptions};

/// JSON facade for language bindings.
///
/// Inputs and outputs use canonical wire JSON shape: snake_case field names and
/// the same DTO structure as the HTTP API. The facade converts typed client
/// errors into redacted [`PortableClientError`] values.
#[derive(Debug, Clone)]
pub struct NotaryClientHandle {
    client: RegistryNotaryClient,
}

impl NotaryClientHandle {
    /// Wrap a typed client.
    #[must_use]
    pub fn new(client: RegistryNotaryClient) -> Self {
        Self { client }
    }

    /// Submit canonical JSON for `POST /claims/evaluate`.
    pub async fn evaluate_json(
        &self,
        request: serde_json::Value,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError> {
        let request = parse_value::<EvaluateRequest>(request)?;
        let options = parse_options(options)?;
        self.client
            .evaluate_dto(request, options)
            .await
            .map(|response| serde_json::to_value(response.body).expect("response serializes"))
            .map_err(|error| error.portable())
    }

    /// Submit canonical JSON for `POST /claims/batch-evaluate`.
    pub async fn batch_evaluate_json(
        &self,
        request: serde_json::Value,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError> {
        let request = parse_value::<BatchEvaluateRequest>(request)?;
        let options = parse_options(options)?;
        self.client
            .batch_evaluate_dto(request, options)
            .await
            .map(|response| serde_json::to_value(response.body).expect("response serializes"))
            .map_err(|error| error.portable())
    }

    /// Submit canonical JSON for `POST /evidence/render`.
    pub async fn render_json(
        &self,
        request: serde_json::Value,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError> {
        let request = parse_value::<RenderRequest>(request)?;
        let options = parse_options(options)?;
        self.client
            .render_dto(request, options)
            .await
            .map(|response| response.body)
            .map_err(|error| error.portable())
    }

    /// Submit canonical JSON for `POST /credentials/issue`.
    pub async fn issue_credential_json(
        &self,
        request: serde_json::Value,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError> {
        let request = parse_value::<CredentialIssueRequest>(request)?;
        let options = parse_options(options)?;
        self.client
            .issue_credential_dto(request, options)
            .await
            .map(|response| serde_json::to_value(response.body).expect("response serializes"))
            .map_err(|error| error.portable())
    }

    /// Fetch `GET /claims`.
    pub async fn list_claims_json(
        &self,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError> {
        let options = parse_options(options)?;
        self.client
            .list_claims(options)
            .await
            .map(|response| serde_json::to_value(response.body).expect("response serializes"))
            .map_err(|error| error.portable())
    }

    /// Fetch `GET /claims/{claim_id}`.
    pub async fn get_claim_json(
        &self,
        claim_id: String,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError> {
        let options = parse_options(options)?;
        self.client
            .get_claim(&claim_id, options)
            .await
            .map(|response| response.body)
            .map_err(|error| error.portable())
    }

    /// Fetch `GET /credentials/status/{credential_id}`.
    pub async fn credential_status_json(
        &self,
        credential_id: String,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, PortableClientError> {
        let options = parse_options(options)?;
        self.client
            .credential_status(&credential_id, options)
            .await
            .map(|response| serde_json::to_value(response.body).expect("response serializes"))
            .map_err(|error| error.portable())
    }
}

fn parse_options(options: serde_json::Value) -> Result<RequestOptions, PortableClientError> {
    parse_value::<RequestOptions>(options)
}

fn parse_value<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, PortableClientError> {
    serde_json::from_value(value).map_err(|_| PortableClientError {
        kind: crate::PortableErrorKind::Decode,
        status: None,
        code: Some("decode.failed".to_string()),
        title: "Failed to decode request JSON".to_string(),
        retryable: false,
        request_id: None,
    })
}
