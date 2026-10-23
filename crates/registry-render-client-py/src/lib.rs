// SPDX-License-Identifier: Apache-2.0
#![deny(unsafe_code)]
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use registry_platform_canonical_json::parse_json_strict;
use render_client_sdk::{BearerToken, RenderClient as CoreClient, RenderClientConfig};
fn fixed() -> PyErr {
    PyRuntimeError::new_err("Render client arguments are invalid")
}
fn mapped(error: render_client_sdk::RenderClientError) -> PyErr {
    PyRuntimeError::new_err(serde_json::to_string(&error).expect("fixed error serializes"))
}
#[pyclass(name = "_RenderClient", module = "registry_render_client")]
struct RenderClient {
    inner: CoreClient,
    runtime: tokio::runtime::Runtime,
}
#[pymethods]
impl RenderClient {
    #[new]
    fn new(config: &str) -> PyResult<Self> {
        let config: RenderClientConfig =
            serde_json::from_value(parse_json_strict(config.as_bytes()).map_err(|_| fixed())?)
                .map_err(|_| fixed())?;
        let inner = CoreClient::new(config).map_err(mapped)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PyRuntimeError::new_err("Render client runtime could not start"))?;
        Ok(Self { inner, runtime })
    }
    fn render(
        &self,
        py: Python<'_>,
        token: String,
        document_type: String,
        request: String,
    ) -> PyResult<String> {
        let token = BearerToken::new(token)
            .map_err(|_| mapped(render_client_sdk::RenderClientError::invalid_request()))?;
        let request = parse_json_strict(request.as_bytes()).map_err(|_| fixed())?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.render(&token, &document_type, &request))
            })
            .map_err(mapped)?;
        serde_json::to_string(&value)
            .map_err(|_| PyRuntimeError::new_err("Render response conversion failed"))
    }
}
#[pyfunction]
fn validate_render_request(document_type: &str, request: &str) -> PyResult<()> {
    let request = parse_json_strict(request.as_bytes()).map_err(|_| fixed())?;
    CoreClient::validate_request(document_type, &request)
        .map(|_| ())
        .map_err(mapped)
}
#[pymodule]
fn registry_render_client(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<RenderClient>()?;
    module.add_function(wrap_pyfunction!(validate_render_request, module)?)?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
