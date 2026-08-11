// SPDX-License-Identifier: Apache-2.0
//! Synchronous Python binding for the canonical Registry Relay V2 client.

use std::collections::BTreeMap;

use pyo3::{
    exceptions::{PyException, PyRuntimeError},
    prelude::*,
    types::{PyBytes, PyDict},
};
use relay_client_sdk::{
    BoundingBox, CollectionContinuation, CollectionContinuationProjection, CollectionPage,
    CollectionRouteProjection, Complete, Conditional, ListRequest, LookupRequest, NotModified,
    RawDocument, RecordFormat, RecordOptions, RelayClient as RustClient,
    RelayClientError as RustClientError, ResourceContinuation, ResourceContinuationProjection,
    ResourceListRequest, ResourcePage, ResponseMetadata, SdmxDataFormat, SdmxDataRequest,
    SdmxStructureKind, SdmxStructureRequest, SearchRequest, StrongEtag,
};
use serde::Serialize;
use serde_json::Value;

mod convert;

use convert::{
    authorization_from_python, config_from_parts, map_client_error, map_config_error,
    python_to_json, serialize_to_python, ConversionError, MappedError,
};

pyo3::create_exception!(
    registry_relay_client,
    RelayClientError,
    PyException,
    "A stable, value-free Registry Relay client failure. Inspect kind and the optional structured attributes."
);

fn to_py_err(py: Python<'_>, mapped: &MappedError) -> PyErr {
    let error = RelayClientError::new_err(mapped.message.clone());
    let instance = error.value(py);
    macro_rules! set_attr {
        ($name:literal, $value:expr) => {
            instance
                .setattr($name, $value)
                .expect("a fresh exception accepts its stable attributes")
        };
    }
    set_attr!("kind", mapped.kind);
    set_attr!("code", mapped.code.as_deref());
    set_attr!("status", mapped.status);
    set_attr!("trace_id", mapped.trace_id.as_deref());
    set_attr!("retry_after_seconds", mapped.retry_after_seconds);
    set_attr!("transport_kind", mapped.transport_kind);
    set_attr!("token_kind", mapped.token_kind);
    error
}

fn conversion_error(py: Python<'_>, kind: &'static str, error: &ConversionError) -> PyErr {
    to_py_err(py, &MappedError::binding(kind, error.message()))
}

fn sdk_error(py: Python<'_>, error: &RustClientError) -> PyErr {
    to_py_err(py, &map_client_error(error))
}

fn parse_etag(py: Python<'_>, value: Option<&str>) -> PyResult<Option<StrongEtag>> {
    value
        .map(|value| {
            StrongEtag::parse(value).map_err(|_| {
                to_py_err(
                    py,
                    &MappedError::binding(
                        "invalid_request",
                        "etag must be a strong quoted SHA-256 entity tag",
                    ),
                )
            })
        })
        .transpose()
}

fn record_format(py: Python<'_>, value: &str) -> PyResult<RecordFormat> {
    match value {
        "json" => Ok(RecordFormat::Json),
        "json-ld" => Ok(RecordFormat::JsonLd),
        "geojson" => Ok(RecordFormat::GeoJsonRfc7946),
        "json-fg" => Ok(RecordFormat::JsonFg),
        _ => Err(to_py_err(
            py,
            &MappedError::binding(
                "invalid_request",
                "format must be json, json-ld, geojson, or json-fg",
            ),
        )),
    }
}

fn record_options(
    py: Python<'_>,
    fields: Option<Vec<String>>,
    access_profile: Option<String>,
    format: &str,
) -> PyResult<RecordOptions> {
    let mut options = RecordOptions::default().format(record_format(py, format)?);
    if let Some(fields) = fields {
        options = options
            .fields(fields)
            .map_err(|error| sdk_error(py, &error))?;
    }
    if let Some(access_profile) = access_profile {
        options = options
            .access_profile(access_profile)
            .map_err(|error| sdk_error(py, &error))?;
    }
    Ok(options)
}

fn string_map(
    py: Python<'_>,
    value: Option<&Bound<'_, PyAny>>,
    what: &str,
) -> PyResult<BTreeMap<String, String>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let value =
        python_to_json(value).map_err(|error| conversion_error(py, "invalid_request", &error))?;
    let Value::Object(value) = value else {
        return Err(to_py_err(
            py,
            &MappedError::binding("invalid_request", format!("{what} must be a mapping")),
        ));
    };
    value
        .into_iter()
        .map(|(name, value)| match value {
            Value::String(value) => Ok((name, value)),
            _ => Err(to_py_err(
                py,
                &MappedError::binding(
                    "invalid_request",
                    format!("every {what} value must be a string"),
                ),
            )),
        })
        .collect()
}

fn bounding_box(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<BoundingBox> {
    let value =
        python_to_json(value).map_err(|error| conversion_error(py, "invalid_request", &error))?;
    let Value::Array(values) = value else {
        return Err(to_py_err(
            py,
            &MappedError::binding("invalid_request", "bbox must be a four-number sequence"),
        ));
    };
    let numbers = values
        .iter()
        .map(Value::as_f64)
        .collect::<Option<Vec<_>>>()
        .filter(|values| values.len() == 4)
        .ok_or_else(|| {
            to_py_err(
                py,
                &MappedError::binding("invalid_request", "bbox must be a four-number sequence"),
            )
        })?;
    BoundingBox::new(numbers[0], numbers[1], numbers[2], numbers[3])
        .map_err(|error| sdk_error(py, &error))
}

fn list_request(
    py: Python<'_>,
    page_size: Option<u32>,
    fields: Option<Vec<String>>,
    access_profile: Option<String>,
    format: &str,
    filters: Option<&Bound<'_, PyAny>>,
) -> PyResult<ListRequest> {
    let options = record_options(py, fields, access_profile, format)?;
    let mut request = ListRequest::default().options(options);
    if let Some(page_size) = page_size {
        request = request
            .page_size(page_size)
            .map_err(|error| sdk_error(py, &error))?;
    }
    for (name, value) in string_map(py, filters, "filter")? {
        request = request
            .filter(name, value)
            .map_err(|error| sdk_error(py, &error))?;
    }
    Ok(request)
}

fn search_request(
    py: Python<'_>,
    bbox: &Bound<'_, PyAny>,
    page_size: Option<u32>,
    fields: Option<Vec<String>>,
    access_profile: Option<String>,
    format: &str,
) -> PyResult<SearchRequest> {
    let options = record_options(py, fields, access_profile, format)?;
    let mut request = SearchRequest::new(bounding_box(py, bbox)?).options(options);
    if let Some(page_size) = page_size {
        request = request
            .page_size(page_size)
            .map_err(|error| sdk_error(py, &error))?;
    }
    Ok(request)
}

fn lookup_request(
    py: Python<'_>,
    selectors: &Bound<'_, PyAny>,
    fields: Option<Vec<String>>,
    access_profile: Option<String>,
    format: &str,
) -> PyResult<LookupRequest> {
    let selectors = python_to_json(selectors)
        .map_err(|error| conversion_error(py, "invalid_request", &error))?;
    let Value::Object(selectors) = selectors else {
        return Err(to_py_err(
            py,
            &MappedError::binding("invalid_request", "selectors must be a mapping"),
        ));
    };
    let mut request =
        LookupRequest::default().options(record_options(py, fields, access_profile, format)?);
    for (name, value) in selectors {
        request = request
            .selector(name, value)
            .map_err(|error| sdk_error(py, &error))?;
    }
    Ok(request)
}

fn set_metadata(dict: &Bound<'_, PyDict>, metadata: &ResponseMetadata) -> PyResult<()> {
    dict.set_item("trace_id", metadata.trace_id().as_str())?;
    dict.set_item("etag", metadata.etag().map(StrongEtag::as_str))?;
    Ok(())
}

fn complete_value<'py>(
    py: Python<'py>,
    value: &impl Serialize,
    metadata: &ResponseMetadata,
) -> PyResult<Bound<'py, PyAny>> {
    let result = PyDict::new(py);
    result.set_item("kind", "complete")?;
    result.set_item("value", serialize_to_python(py, value)?)?;
    set_metadata(&result, metadata)?;
    Ok(result.into_any())
}

fn complete_raw<'py>(
    py: Python<'py>,
    value: &RawDocument,
    metadata: &ResponseMetadata,
) -> PyResult<Bound<'py, PyAny>> {
    let result = PyDict::new(py);
    result.set_item("kind", "complete")?;
    result.set_item("body", PyBytes::new(py, value.as_bytes()))?;
    result.set_item("media_type", value.media_type())?;
    set_metadata(&result, metadata)?;
    Ok(result.into_any())
}

fn not_modified<'py>(py: Python<'py>, value: &NotModified) -> PyResult<Bound<'py, PyAny>> {
    let result = PyDict::new(py);
    result.set_item("kind", "not_modified")?;
    result.set_item("etag", value.etag.as_str())?;
    result.set_item("trace_id", value.trace_id.as_str())?;
    Ok(result.into_any())
}

fn conditional_value<'py, T: Serialize>(
    py: Python<'py>,
    value: &Conditional<T>,
) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Conditional::Complete(Complete { value, metadata }) => complete_value(py, value, metadata),
        Conditional::NotModified(value) => not_modified(py, value),
    }
}

fn conditional_raw<'py>(
    py: Python<'py>,
    value: &Conditional<RawDocument>,
) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Conditional::Complete(Complete { value, metadata }) => complete_raw(py, value, metadata),
        Conditional::NotModified(value) => not_modified(py, value),
    }
}

fn resource_page<'py, T: Serialize>(
    py: Python<'py>,
    value: Conditional<ResourcePage<T>>,
) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Conditional::NotModified(value) => not_modified(py, &value),
        Conditional::Complete(Complete { value, metadata }) => {
            let result = PyDict::new(py);
            result.set_item("kind", "complete")?;
            result.set_item("value", serialize_to_python(py, &value.value)?)?;
            set_metadata(&result, &metadata)?;
            if let Some(continuation) = value.continuation {
                result.set_item(
                    "continuation",
                    serialize_to_python(py, &continuation.projection())?,
                )?;
            } else {
                result.set_item("continuation", py.None())?;
            }
            Ok(result.into_any())
        }
    }
}

fn collection_page<'py, T: Serialize>(
    py: Python<'py>,
    value: Conditional<CollectionPage<T>>,
) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Conditional::NotModified(value) => not_modified(py, &value),
        Conditional::Complete(Complete { value, metadata }) => {
            let result = PyDict::new(py);
            result.set_item("kind", "complete")?;
            result.set_item("value", serialize_to_python(py, &value.value)?)?;
            set_metadata(&result, &metadata)?;
            if let Some(continuation) = value.continuation {
                result.set_item(
                    "continuation",
                    serialize_to_python(py, &continuation.projection())?,
                )?;
            } else {
                result.set_item("continuation", py.None())?;
            }
            Ok(result.into_any())
        }
    }
}

/// One deployment-bound Relay client with one private current-thread runtime.
#[pyclass(name = "RelayClient", module = "registry_relay_client")]
struct RelayClient {
    inner: RustClient,
    runtime: tokio::runtime::Runtime,
}

#[pymethods]
impl RelayClient {
    #[new]
    #[pyo3(signature = (
        base_url,
        authorization=None,
        request_timeout_seconds=None,
        connect_timeout_seconds=None,
        user_agent=None,
        max_response_bytes=None,
        trusted_root_certificates=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        base_url: &str,
        authorization: Option<&Bound<'_, PyAny>>,
        request_timeout_seconds: Option<f64>,
        connect_timeout_seconds: Option<f64>,
        user_agent: Option<String>,
        max_response_bytes: Option<u64>,
        trusted_root_certificates: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let (authorization, private_key_jwt_trusted_root_certificates) =
            authorization_from_python(authorization)
                .map_err(|error| conversion_error(py, "configuration", &error))?;
        let config = config_from_parts(
            base_url,
            &authorization,
            private_key_jwt_trusted_root_certificates,
            request_timeout_seconds,
            connect_timeout_seconds,
            user_agent,
            max_response_bytes,
            trusted_root_certificates,
        )
        .map_err(|error| to_py_err(py, &map_config_error(&error)))?;
        let inner = py
            .detach(|| RustClient::new(config))
            .map_err(|error| sdk_error(py, &error))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                PyRuntimeError::new_err("the client's internal runtime could not start")
            })?;
        Ok(Self { inner, runtime })
    }

    fn health<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let value = py
            .detach(|| self.runtime.block_on(self.inner.health()))
            .map_err(|error| sdk_error(py, &error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    fn ready<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let value = py
            .detach(|| self.runtime.block_on(self.inner.ready()))
            .map_err(|error| sdk_error(py, &error))?;
        complete_value(py, &value.value, &value.metadata)
    }

    #[pyo3(signature = (etag=None))]
    fn openapi<'py>(&self, py: Python<'py>, etag: Option<&str>) -> PyResult<Bound<'py, PyAny>> {
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| self.runtime.block_on(self.inner.openapi(etag.as_ref())))
            .map_err(|error| sdk_error(py, &error))?;
        conditional_raw(py, &value)
    }

    #[pyo3(signature = (etag=None))]
    fn service_metadata<'py>(
        &self,
        py: Python<'py>,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.service_metadata(etag.as_ref()))
            })
            .map_err(|error| sdk_error(py, &error))?;
        conditional_value(py, &value)
    }

    #[pyo3(signature = (page_size=None, etag=None))]
    fn resources<'py>(
        &self,
        py: Python<'py>,
        page_size: Option<u32>,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut request = ResourceListRequest::default();
        if let Some(page_size) = page_size {
            request = request
                .page_size(page_size)
                .map_err(|error| sdk_error(py, &error))?;
        }
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.resources(request, etag.as_ref()))
            })
            .map_err(|error| sdk_error(py, &error))?;
        resource_page(py, value)
    }

    #[pyo3(signature = (continuation, etag=None))]
    fn continue_resources<'py>(
        &self,
        py: Python<'py>,
        continuation: &Bound<'_, PyAny>,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let continuation = python_to_json(continuation)
            .map_err(|error| conversion_error(py, "invalid_request", &error))?;
        let projection: ResourceContinuationProjection = serde_json::from_value(continuation)
            .map_err(|_| {
                to_py_err(
                    py,
                    &MappedError::binding(
                        "invalid_request",
                        "resource continuation must be an exact cursor mapping",
                    ),
                )
            })?;
        let continuation = ResourceContinuation::try_from_projection(projection)
            .map_err(|error| sdk_error(py, &error))?;
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.continue_resources(&continuation, etag.as_ref()))
            })
            .map_err(|error| sdk_error(py, &error))?;
        resource_page(py, value)
    }

    #[pyo3(signature = (resource, etag=None))]
    fn resource<'py>(
        &self,
        py: Python<'py>,
        resource: &str,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.resource(resource, etag.as_ref()))
            })
            .map_err(|error| sdk_error(py, &error))?;
        conditional_value(py, &value)
    }

    #[pyo3(signature = (
        resource, *, page_size=None, fields=None, access_profile=None, format="json",
        filters=None, etag=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn list_records<'py>(
        &self,
        py: Python<'py>,
        resource: &str,
        page_size: Option<u32>,
        fields: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
        filters: Option<&Bound<'_, PyAny>>,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request = list_request(py, page_size, fields, access_profile, format, filters)?;
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.list_records(resource, &request, etag.as_ref()))
            })
            .map_err(|error| sdk_error(py, &error))?;
        collection_page(py, value)
    }

    #[pyo3(signature = (continuation, etag=None))]
    fn continue_list_records<'py>(
        &self,
        py: Python<'py>,
        continuation: &Bound<'_, PyAny>,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.continue_collection(py, continuation, etag, "list")
    }

    #[pyo3(signature = (
        resource, search, *, bbox, page_size=None, fields=None, access_profile=None,
        format="json", etag=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn search<'py>(
        &self,
        py: Python<'py>,
        resource: &str,
        search: &str,
        bbox: &Bound<'_, PyAny>,
        page_size: Option<u32>,
        fields: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request = search_request(py, bbox, page_size, fields, access_profile, format)?;
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.search_records(
                    resource,
                    search,
                    &request,
                    etag.as_ref(),
                ))
            })
            .map_err(|error| sdk_error(py, &error))?;
        collection_page(py, value)
    }

    #[pyo3(signature = (continuation, etag=None))]
    fn continue_search<'py>(
        &self,
        py: Python<'py>,
        continuation: &Bound<'_, PyAny>,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.continue_collection(py, continuation, etag, "search")
    }

    #[pyo3(signature = (
        resource, record_identifier, *, fields=None, access_profile=None, format="json", etag=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn read_record<'py>(
        &self,
        py: Python<'py>,
        resource: &str,
        record_identifier: &str,
        fields: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let options = record_options(py, fields, access_profile, format)?;
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.read_record(
                    resource,
                    record_identifier,
                    &options,
                    etag.as_ref(),
                ))
            })
            .map_err(|error| sdk_error(py, &error))?;
        conditional_value(py, &value)
    }

    #[pyo3(signature = (
        resource, lookup, selectors, *, fields=None, access_profile=None, format="json", etag=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn lookup<'py>(
        &self,
        py: Python<'py>,
        resource: &str,
        lookup: &str,
        selectors: &Bound<'_, PyAny>,
        fields: Option<Vec<String>>,
        access_profile: Option<String>,
        format: &str,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request = lookup_request(py, selectors, fields, access_profile, format)?;
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| {
                self.runtime.block_on(self.inner.lookup_record(
                    resource,
                    lookup,
                    &request,
                    etag.as_ref(),
                ))
            })
            .map_err(|error| sdk_error(py, &error))?;
        conditional_value(py, &value)
    }

    #[pyo3(signature = (artifact_identifier, etag=None))]
    fn artifact<'py>(
        &self,
        py: Python<'py>,
        artifact_identifier: &str,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.artifact(artifact_identifier, etag.as_ref()))
            })
            .map_err(|error| sdk_error(py, &error))?;
        conditional_raw(py, &value)
    }

    #[pyo3(signature = (
        agency, resource, version, *, key=None, constraints=None, offset=None, limit=None,
        dimension_at_observation=None, format="json", etag=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn sdmx_data<'py>(
        &self,
        py: Python<'py>,
        agency: &str,
        resource: &str,
        version: &str,
        key: Option<String>,
        constraints: Option<&Bound<'_, PyAny>>,
        offset: Option<u32>,
        limit: Option<u32>,
        dimension_at_observation: Option<String>,
        format: &str,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut request = SdmxDataRequest::new(agency, resource, version)
            .map_err(|error| sdk_error(py, &error))?;
        if let Some(key) = key {
            request = request.keyed(key).map_err(|error| sdk_error(py, &error))?;
        }
        for (name, value) in string_map(py, constraints, "constraint")? {
            request = request
                .constraint(name, value)
                .map_err(|error| sdk_error(py, &error))?;
        }
        if let Some(offset) = offset {
            request = request.offset(offset);
        }
        if let Some(limit) = limit {
            request = request
                .limit(limit)
                .map_err(|error| sdk_error(py, &error))?;
        }
        if let Some(value) = dimension_at_observation {
            request = request
                .dimension_at_observation(value)
                .map_err(|error| sdk_error(py, &error))?;
        }
        request = request.format(match format {
            "json" => SdmxDataFormat::Json,
            "csv" => SdmxDataFormat::Csv,
            _ => {
                return Err(to_py_err(
                    py,
                    &MappedError::binding(
                        "invalid_request",
                        "SDMX data format must be json or csv",
                    ),
                ))
            }
        });
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.sdmx_data(&request, etag.as_ref()))
            })
            .map_err(|error| sdk_error(py, &error))?;
        conditional_raw(py, &value)
    }

    #[pyo3(signature = (kind, agency, resource, version, *, etag=None))]
    fn sdmx_structure<'py>(
        &self,
        py: Python<'py>,
        kind: &str,
        agency: &str,
        resource: &str,
        version: &str,
        etag: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let kind = match kind {
            "dataflow" => SdmxStructureKind::Dataflow,
            "datastructure" => SdmxStructureKind::DataStructure,
            _ => {
                return Err(to_py_err(
                    py,
                    &MappedError::binding(
                        "invalid_request",
                        "SDMX structure kind must be dataflow or datastructure",
                    ),
                ))
            }
        };
        let request = SdmxStructureRequest::new(kind, agency, resource, version)
            .map_err(|error| sdk_error(py, &error))?;
        let etag = parse_etag(py, etag)?;
        let value = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.sdmx_structure(&request, etag.as_ref()))
            })
            .map_err(|error| sdk_error(py, &error))?;
        conditional_raw(py, &value)
    }
}

impl RelayClient {
    fn continue_collection<'py>(
        &self,
        py: Python<'py>,
        continuation: &Bound<'_, PyAny>,
        etag: Option<&str>,
        kind: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let value = python_to_json(continuation)
            .map_err(|error| conversion_error(py, "invalid_request", &error))?;
        let Value::Object(object) = &value else {
            return Err(to_py_err(
                py,
                &MappedError::binding("invalid_request", "continuation must be a mapping"),
            ));
        };
        if object
            .keys()
            .any(|field| !["route", "cursor", "format", "accessProfile"].contains(&field.as_str()))
        {
            return Err(to_py_err(
                py,
                &MappedError::binding("invalid_request", "continuation is invalid"),
            ));
        }
        let Some(Value::Object(route)) = object.get("route") else {
            return Err(to_py_err(
                py,
                &MappedError::binding("invalid_request", "continuation is invalid"),
            ));
        };
        let route_fields = match route.get("kind").and_then(Value::as_str) {
            Some("records") => &["kind", "resource"][..],
            Some("search") => &["kind", "resource", "search"][..],
            _ => {
                return Err(to_py_err(
                    py,
                    &MappedError::binding("invalid_request", "continuation is invalid"),
                ));
            }
        };
        if route.len() != route_fields.len()
            || route
                .keys()
                .any(|field| !route_fields.contains(&field.as_str()))
            || object
                .get("accessProfile")
                .is_some_and(|value| !value.is_string())
        {
            return Err(to_py_err(
                py,
                &MappedError::binding("invalid_request", "continuation is invalid"),
            ));
        }
        let projection: CollectionContinuationProjection =
            serde_json::from_value(value).map_err(|_| {
                to_py_err(
                    py,
                    &MappedError::binding("invalid_request", "continuation is invalid"),
                )
            })?;
        let route_matches = matches!(
            (&projection.route, kind),
            (CollectionRouteProjection::Records { .. }, "list")
                | (CollectionRouteProjection::Search { .. }, "search")
        );
        if !route_matches {
            return Err(to_py_err(
                py,
                &MappedError::binding(
                    "invalid_request",
                    "continuation does not match the method that consumes it",
                ),
            ));
        }
        let continuation = CollectionContinuation::try_from_projection(projection)
            .map_err(|error| sdk_error(py, &error))?;
        let etag = parse_etag(py, etag)?;
        let response = py
            .detach(|| {
                self.runtime
                    .block_on(self.inner.continue_collection(&continuation, etag.as_ref()))
            })
            .map_err(|error| sdk_error(py, &error))?;
        collection_page(py, response)
    }
}

#[pymodule]
pub fn registry_relay_client(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<RelayClient>()?;
    module.add(
        "RelayClientError",
        module.py().get_type::<RelayClientError>(),
    )?;
    Ok(())
}
