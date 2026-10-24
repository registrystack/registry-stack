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
    pub fn new(config: Value) -> Result<Self> {
        let config: RenderClientConfig = serde_json::from_value(config)
            .map_err(|_| Error::from_reason("Render client configuration is invalid"))?;
        CoreClient::new(config)
            .map(|inner| Self { inner })
            .map_err(mapped)
    }
    #[napi(ts_return_type = "Promise<import('./client').RenderedDocument>")]
    pub async fn render(
        &self,
        token: String,
        document_type: String,
        request: Value,
    ) -> Result<Value> {
        let token = BearerToken::new(token)
            .map_err(|_| mapped(registry_render_client::RenderClientError::invalid_request()))?;
        let result = self
            .inner
            .render(&token, &document_type, &request)
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
