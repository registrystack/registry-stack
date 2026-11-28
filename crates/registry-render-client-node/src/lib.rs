// SPDX-License-Identifier: Apache-2.0
#![deny(unsafe_code)]
use napi::{Error, Result};
use napi_derive::napi;
use registry_render_client::{BearerToken, RenderClient as CoreClient, RenderClientConfig};
use serde_json::Value;
fn mapped(error: registry_render_client::RenderClientError) -> Error {
    Error::from_reason(serde_json::to_string(&error).expect("fixed error serializes"))
}
#[napi(js_name = "RenderClient")]
pub struct RenderClient {
    inner: CoreClient,
}
#[napi]
impl RenderClient {
    #[napi(
        constructor,
        ts_args_type = "config: import('./client').RenderClientConfig"
    )]
    pub fn new(mut config: Value) -> Result<Self> {
        let invalid = || Error::from_reason("Render client configuration is invalid");
        let refuse_development_peer = config
            .as_object_mut()
            .ok_or_else(invalid)?
            .remove("refuseDevelopmentPeer")
            .map(|value| value.as_bool().ok_or_else(invalid))
            .transpose()?
            .unwrap_or(false);
        let config: RenderClientConfig = serde_json::from_value(config).map_err(|_| invalid())?;
        let peer_policy = if refuse_development_peer {
            registry_render_client::PeerPolicy::RefuseDevelopmentPeer
        } else {
            registry_render_client::PeerPolicy::AcceptDevelopmentPeer
        };
        CoreClient::new(config, peer_policy)
            .map(|inner| Self { inner })
            .map_err(mapped)
    }
    #[napi(ts_return_type = "Promise<import('./client').RenderedDocument>")]
    pub async fn render(
        &self,
        token: String,
        document_type: String,
        request: Value,
        correlation_key: Option<String>,
    ) -> Result<Value> {
        let token = BearerToken::new(token)
            .map_err(|_| mapped(registry_render_client::RenderClientError::invalid_request()))?;
        let result = self
            .inner
            .render(&token, &document_type, &request, correlation_key.as_deref())
            .await
            .map_err(mapped)?;
        serde_json::to_value(result)
            .map_err(|_| Error::from_reason("Render response conversion failed"))
    }
    #[napi(ts_return_type = "Promise<import('./client').SealedDocument>")]
    pub async fn seal(
        &self,
        token: String,
        document_type: String,
        request: Value,
        correlation_key: Option<String>,
    ) -> Result<Value> {
        let token = BearerToken::new(token)
            .map_err(|_| mapped(registry_render_client::RenderClientError::invalid_request()))?;
        let result = self
            .inner
            .seal(&token, &document_type, &request, correlation_key.as_deref())
            .await
            .map_err(mapped)?;
        serde_json::to_value(result)
            .map_err(|_| Error::from_reason("Render response conversion failed"))
    }
}
#[napi]
pub fn validate_render_request(document_type: String, request: Value) -> Result<()> {
    CoreClient::validate_request(&document_type, &request)
        .map(|_| ())
        .map_err(mapped)
}
#[napi]
pub fn validate_correlation_key(correlation_key: Option<String>) -> Result<()> {
    CoreClient::validate_correlation_key(correlation_key.as_deref()).map_err(mapped)
}
