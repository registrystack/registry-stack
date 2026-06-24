//! HTTP security helpers for Axum/Tower registry services.
//!
//! The crate keeps browser-facing defaults small and explicit: CORS validation,
//! common security headers, request-body limits, and RFC 9457-style
//! Problem Details responses.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use axum::http::{Method, Request, Response, StatusCode};
use axum::response::IntoResponse;
use serde::Serialize;
use serde_json::Value;
use tower::{Layer, Service};
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

pub const DEFAULT_REQUEST_BODY_LIMIT_BYTES: usize = 1024 * 1024;
pub const PROBLEM_CODE_EXTENSION: &str = "code";
pub const PROBLEM_REQUEST_ID_EXTENSION: &str = "request_id";

#[derive(Debug, Clone, Default)]
pub struct CorsPolicy {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<Method>,
    pub allowed_headers: Vec<HeaderName>,
    pub allow_credentials: bool,
}

impl CorsPolicy {
    pub fn validate(&self) -> Result<(), CorsValidationError> {
        for origin in &self.allowed_origins {
            if origin == "*" {
                return Err(CorsValidationError::WildcardOrigin);
            }
            let _value = HeaderValue::from_str(origin)
                .map_err(|_| CorsValidationError::MalformedOrigin(origin.clone()))?;
            let parsed = url::Url::parse(origin)
                .map_err(|_| CorsValidationError::MalformedOrigin(origin.clone()))?;
            match parsed.scheme() {
                "https" => {}
                "http" if is_loopback_origin(&parsed) => {}
                _ => {
                    return Err(CorsValidationError::MalformedOrigin(origin.clone()));
                }
            }
            if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
                return Err(CorsValidationError::MalformedOrigin(origin.clone()));
            }
        }
        if self.allow_credentials && self.allowed_headers.is_empty() {
            return Err(CorsValidationError::CredentialedWildcardHeaders);
        }
        Ok(())
    }

    /// Build a [`CorsLayer`] from this policy, panicking if the policy is invalid.
    ///
    /// # Panics
    ///
    /// Panics if the policy fails validation (e.g. wildcard origin, credentialed
    /// request without explicit allowed headers). Use [`try_layer`](Self::try_layer)
    /// to handle the error gracefully instead.
    #[deprecated(
        note = "panics on invalid policy; use try_layer() and handle the CorsValidationError"
    )]
    pub fn layer(&self) -> CorsLayer {
        self.validate()
            .expect("invalid CORS policy must not be converted into a layer");
        self.layer_unchecked()
    }

    pub fn try_layer(&self) -> Result<CorsLayer, CorsValidationError> {
        self.validate()?;
        Ok(self.layer_unchecked())
    }

    fn layer_unchecked(&self) -> CorsLayer {
        if self.allowed_origins.is_empty() {
            return CorsLayer::new();
        }
        let origins: Vec<HeaderValue> = self
            .allowed_origins
            .iter()
            .filter_map(|origin| HeaderValue::from_str(origin).ok())
            .collect();
        let methods = if self.allowed_methods.is_empty() {
            vec![Method::GET, Method::POST, Method::OPTIONS]
        } else {
            self.allowed_methods.clone()
        };
        let layer = CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(methods)
            .allow_credentials(self.allow_credentials);
        if self.allowed_headers.is_empty() {
            layer.allow_headers(Any)
        } else {
            layer.allow_headers(self.allowed_headers.clone())
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CorsValidationError {
    #[error("wildcard CORS origin is not allowed")]
    WildcardOrigin,
    #[error("credentialed CORS requires explicit allowed headers")]
    CredentialedWildcardHeaders,
    #[error("malformed CORS origin: {0}")]
    MalformedOrigin(String),
}

#[derive(Debug, Clone)]
pub struct CspBuilder {
    default_src: Vec<String>,
    script_src: Vec<String>,
    style_src: Vec<String>,
    img_src: Vec<String>,
    connect_src: Vec<String>,
}

impl CspBuilder {
    #[must_use]
    pub fn restrictive() -> Self {
        Self {
            default_src: vec!["'self'".to_string()],
            script_src: vec!["'self'".to_string()],
            style_src: vec!["'self'".to_string()],
            img_src: vec!["'self'".to_string(), "data:".to_string()],
            connect_src: vec!["'self'".to_string()],
        }
    }

    pub fn header_value(&self) -> HeaderValue {
        HeaderValue::from_str(&format!(
            "default-src {}; script-src {}; style-src {}; img-src {}; connect-src {}; object-src 'none'; frame-ancestors 'none'",
            self.default_src.join(" "),
            self.script_src.join(" "),
            self.style_src.join(" "),
            self.img_src.join(" "),
            self.connect_src.join(" "),
        ))
        .expect("CSP built from static directive names is a valid header")
    }
}

/// Default HSTS value applied by [`security_headers`]: two-year max-age with
/// `includeSubDomains`. Use [`SecurityHeadersLayer::without_hsts`] to disable
/// HSTS for deployments that terminate TLS upstream or serve plain HTTP.
pub const DEFAULT_HSTS_VALUE: &str = "max-age=63072000; includeSubDomains";

pub fn security_headers(csp: CspBuilder) -> SecurityHeadersLayer {
    SecurityHeadersLayer {
        csp: csp.header_value(),
        hsts: Some(HeaderValue::from_static(DEFAULT_HSTS_VALUE)),
    }
}

#[derive(Debug, Clone)]
pub struct SecurityHeadersLayer {
    csp: HeaderValue,
    /// When `Some`, a `Strict-Transport-Security` header is inserted (if not
    /// already present) by the service. Set to `None` via
    /// [`SecurityHeadersLayer::without_hsts`] for deployments that terminate
    /// TLS upstream or serve plain HTTP.
    hsts: Option<HeaderValue>,
}

impl SecurityHeadersLayer {
    /// Disable the default `Strict-Transport-Security` header for deployments
    /// that terminate TLS upstream (e.g. a load balancer or reverse proxy) or
    /// that intentionally serve plain HTTP (e.g. internal cluster traffic).
    #[must_use]
    pub fn without_hsts(mut self) -> Self {
        self.hsts = None;
        self
    }

    /// Override the `Strict-Transport-Security` header value.
    ///
    /// The default is `"max-age=63072000; includeSubDomains"`. Use this to
    /// add `preload` or reduce `max-age` for staged rollouts.
    #[must_use]
    pub fn with_hsts(mut self, value: HeaderValue) -> Self {
        self.hsts = Some(value);
        self
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService {
            inner,
            csp: self.csp.clone(),
            hsts: self.hsts.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityHeadersService<S> {
    inner: S,
    csp: HeaderValue,
    hsts: Option<HeaderValue>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SecurityHeadersService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let future = self.inner.call(request);
        let csp = self.csp.clone();
        let hsts = self.hsts.clone();
        Box::pin(async move {
            let mut response = future.await?;
            insert_if_missing(
                &mut response,
                HeaderName::from_static("content-security-policy"),
                csp,
            );
            insert_if_missing(
                &mut response,
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );
            insert_if_missing(
                &mut response,
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("no-referrer"),
            );
            insert_if_missing(
                &mut response,
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("DENY"),
            );
            insert_if_missing(
                &mut response,
                HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static(
                    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
                ),
            );
            insert_if_missing(
                &mut response,
                HeaderName::from_static("cross-origin-opener-policy"),
                HeaderValue::from_static("same-origin"),
            );
            if let Some(hsts_value) = hsts {
                insert_if_missing(
                    &mut response,
                    HeaderName::from_static("strict-transport-security"),
                    hsts_value,
                );
            }
            Ok(response)
        })
    }
}

fn insert_if_missing<B>(response: &mut Response<B>, name: HeaderName, value: HeaderValue) {
    if !response.headers().contains_key(&name) {
        response.headers_mut().insert(name, value);
    }
}

pub fn corp_conditional() -> CorpConditionalLayer {
    CorpConditionalLayer
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CorpConditionalLayer;

impl<S> Layer<S> for CorpConditionalLayer {
    type Service = CorpConditionalService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CorpConditionalService { inner }
    }
}

#[derive(Debug, Clone)]
pub struct CorpConditionalService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CorpConditionalService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let future = self.inner.call(request);
        Box::pin(async move {
            let mut response = future.await?;
            apply_conditional_corp(&mut response);
            Ok(response)
        })
    }
}

pub fn apply_conditional_corp<B>(response: &mut Response<B>) {
    let value = if response
        .headers()
        .contains_key("access-control-allow-origin")
    {
        HeaderValue::from_static("cross-origin")
    } else {
        HeaderValue::from_static("same-origin")
    };
    response.headers_mut().insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        value,
    );
}

pub fn request_body_limit(max_bytes: usize) -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(max_bytes)
}

pub fn request_body_limit_default() -> RequestBodyLimitLayer {
    request_body_limit(DEFAULT_REQUEST_BODY_LIMIT_BYTES)
}

pub fn hsts_header(max_age: u64, include_subdomains: bool, preload: bool) -> HeaderValue {
    let mut value = format!("max-age={max_age}");
    if include_subdomains {
        value.push_str("; includeSubDomains");
    }
    if preload {
        value.push_str("; preload");
    }
    HeaderValue::from_str(&value).expect("HSTS directives are valid header bytes")
}

pub fn apply_hsts<B>(response: &mut Response<B>, value: HeaderValue) {
    insert_if_missing(
        response,
        HeaderName::from_static("strict-transport-security"),
        value,
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossOriginIsolation {
    Disabled,
    RequireCorp,
    Credentialless,
}

pub fn apply_cross_origin_isolation<B>(response: &mut Response<B>, mode: CrossOriginIsolation) {
    if mode == CrossOriginIsolation::Disabled {
        return;
    }
    insert_if_missing(
        response,
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    let coep = match mode {
        CrossOriginIsolation::RequireCorp => "require-corp",
        CrossOriginIsolation::Credentialless => "credentialless",
        CrossOriginIsolation::Disabled => return,
    };
    insert_if_missing(
        response,
        HeaderName::from_static("cross-origin-embedder-policy"),
        HeaderValue::from_static(coep),
    );
}

#[derive(Debug, Clone, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    #[serde(serialize_with = "serialize_status_code")]
    pub status: StatusCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct ProductProblemBuilder {
    base_uri: String,
    code: String,
    title: String,
    status: StatusCode,
    detail: Option<String>,
    request_id: Option<String>,
    extra: BTreeMap<String, Value>,
}

impl ProductProblemBuilder {
    /// Start a product-owned RFC 9457 Problem Details response.
    ///
    /// The response `type` is derived as `{base_uri}/{code}`, and the stable
    /// product code is always emitted as the `code` extension member.
    #[must_use]
    pub fn new(
        base_uri: impl Into<String>,
        code: impl Into<String>,
        title: impl Into<String>,
        status: StatusCode,
    ) -> Self {
        Self {
            base_uri: base_uri.into(),
            code: code.into(),
            title: title.into(),
            status,
            detail: None,
            request_id: None,
            extra: BTreeMap::new(),
        }
    }

    /// Set public response detail.
    ///
    /// Pass only client-safe text. Server causes, upstream messages, secrets,
    /// and raw validation internals belong in service logs, not this field.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    #[must_use]
    pub fn with_extension(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    #[must_use]
    pub fn build(self) -> Problem {
        let type_uri = product_problem_type_uri(&self.base_uri, &self.code);
        let mut problem = Problem::new(&type_uri, &self.title, self.status);
        problem.detail = self.detail;
        problem.extra = self.extra;
        if let Some(request_id) = self.request_id {
            problem.extra.insert(
                PROBLEM_REQUEST_ID_EXTENSION.to_string(),
                Value::String(request_id),
            );
        }
        problem
            .extra
            .insert(PROBLEM_CODE_EXTENSION.to_string(), Value::String(self.code));
        problem
    }
}

impl From<ProductProblemBuilder> for Problem {
    fn from(builder: ProductProblemBuilder) -> Self {
        builder.build()
    }
}

impl Problem {
    #[must_use]
    pub fn new(type_uri: &str, title: &str, status: StatusCode) -> Self {
        Self {
            type_uri: type_uri.to_string(),
            title: title.to_string(),
            status,
            detail: None,
            instance: None,
            extra: BTreeMap::new(),
        }
    }

    #[must_use]
    /// Set public response detail.
    ///
    /// Pass only client-safe text. Server causes, upstream messages, secrets,
    /// and raw validation internals belong in service logs, not this field.
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    #[must_use]
    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    pub fn into_response(self) -> axum::response::Response {
        let status = self.status;
        let mut response = (status, axum::Json(self)).into_response();
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

fn product_problem_type_uri(base_uri: &str, code: &str) -> String {
    format!("{}/{}", base_uri.trim_end_matches('/'), code)
}

fn serialize_status_code<S>(status: &StatusCode, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_u16(status.as_u16())
}

pub mod problem {
    pub use super::{
        Problem, ProductProblemBuilder, PROBLEM_CODE_EXTENSION, PROBLEM_REQUEST_ID_EXTENSION,
    };
}

pub async fn body_limit_problem_response(_request: Request<Body>) -> Response<Body> {
    Problem::new(
        "https://registry-platform.dev/problems/request/body-too-large",
        "Payload Too Large",
        StatusCode::PAYLOAD_TOO_LARGE,
    )
    .detail("request body exceeds the configured limit")
    .into_response()
}

fn is_loopback_origin(url: &url::Url) -> bool {
    let Some(host) = url.host() else {
        return false;
    };
    match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cors_validation_rejects_localhost_prefix_attack() {
        let policy = CorsPolicy {
            allowed_origins: vec!["http://localhost.evil.test".to_string()],
            allowed_methods: Vec::new(),
            allowed_headers: Vec::new(),
            allow_credentials: true,
        };
        assert!(matches!(
            policy.validate(),
            Err(CorsValidationError::MalformedOrigin(_))
        ));
    }

    #[test]
    fn cors_validation_accepts_loopback_dev_origin() {
        let policy = CorsPolicy {
            allowed_origins: vec![
                "http://localhost:3000".to_string(),
                "http://127.0.0.1:3000".to_string(),
            ],
            allowed_methods: Vec::new(),
            allowed_headers: Vec::new(),
            allow_credentials: false,
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn problem_response_uses_problem_json_content_type() {
        let response =
            Problem::new("about:blank", "Bad Request", StatusCode::BAD_REQUEST).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
    }

    #[test]
    fn problem_response_serialises_type_title_status_and_detail() {
        let value = serde_json::to_value(
            Problem::new(
                "https://registry-platform.dev/problems/test",
                "Test Error",
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .detail("something was wrong"),
        )
        .expect("problem serializes");

        assert_eq!(value["type"], "https://registry-platform.dev/problems/test");
        assert_eq!(value["title"], "Test Error");
        assert_eq!(value["status"], 422);
        assert_eq!(value["detail"], "something was wrong");
    }

    #[test]
    fn product_problem_builder_adds_stable_code_and_request_id_extensions() {
        let value = serde_json::to_value(
            ProductProblemBuilder::new(
                "https://registry-relay.dev/problems/",
                "auth.missing_credential",
                "Authentication Required",
                StatusCode::UNAUTHORIZED,
            )
            .detail("authentication credentials are required")
            .request_id("req_123")
            .with_extension("code", Value::String("auth.product_specific".to_string()))
            .with_extension("retryable", Value::Bool(false))
            .build(),
        )
        .expect("product problem serializes");

        assert_eq!(
            value["type"],
            "https://registry-relay.dev/problems/auth.missing_credential"
        );
        assert_eq!(value["title"], "Authentication Required");
        assert_eq!(value["status"], 401);
        assert_eq!(value["detail"], "authentication credentials are required");
        assert_eq!(value["code"], "auth.missing_credential");
        assert_eq!(value["request_id"], "req_123");
        assert_eq!(value["retryable"], false);
    }

    #[test]
    fn cors_rejects_wildcard() {
        let policy = CorsPolicy {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: Vec::new(),
            allowed_headers: Vec::new(),
            allow_credentials: false,
        };
        assert!(matches!(
            policy.validate(),
            Err(CorsValidationError::WildcardOrigin)
        ));
    }

    #[test]
    fn credentialed_cors_rejects_wildcard_headers() {
        let policy = CorsPolicy {
            allowed_origins: vec!["https://app.example.test".to_string()],
            allowed_methods: Vec::new(),
            allowed_headers: Vec::new(),
            allow_credentials: true,
        };
        assert!(matches!(
            policy.validate(),
            Err(CorsValidationError::CredentialedWildcardHeaders)
        ));
    }

    #[test]
    #[should_panic(expected = "invalid CORS policy")]
    #[allow(deprecated)]
    fn credentialed_cors_layer_rejects_wildcard_headers() {
        let _layer = CorsPolicy {
            allowed_origins: vec!["https://app.example.test".to_string()],
            allowed_methods: Vec::new(),
            allowed_headers: Vec::new(),
            allow_credentials: true,
        }
        .layer();
    }

    #[test]
    fn cors_try_layer_returns_validation_error_instead_of_panicking() {
        let err = CorsPolicy {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: Vec::new(),
            allowed_headers: Vec::new(),
            allow_credentials: false,
        }
        .try_layer()
        .expect_err("wildcard origin rejects");
        assert!(matches!(err, CorsValidationError::WildcardOrigin));
    }

    #[test]
    fn hsts_and_cross_origin_isolation_helpers_set_headers_without_overwriting() {
        let mut response = Response::new(());
        apply_hsts(&mut response, hsts_header(31_536_000, true, true));
        apply_cross_origin_isolation(&mut response, CrossOriginIsolation::RequireCorp);

        assert_eq!(
            response.headers().get("strict-transport-security").unwrap(),
            "max-age=31536000; includeSubDomains; preload"
        );
        assert_eq!(
            response
                .headers()
                .get("cross-origin-opener-policy")
                .unwrap(),
            "same-origin"
        );
        assert_eq!(
            response
                .headers()
                .get("cross-origin-embedder-policy")
                .unwrap(),
            "require-corp"
        );

        response.headers_mut().insert(
            "cross-origin-embedder-policy",
            HeaderValue::from_static("credentialless"),
        );
        apply_cross_origin_isolation(&mut response, CrossOriginIsolation::RequireCorp);
        assert_eq!(
            response
                .headers()
                .get("cross-origin-embedder-policy")
                .unwrap(),
            "credentialless"
        );
    }

    #[test]
    fn request_body_limit_default_is_one_mebibyte() {
        assert_eq!(DEFAULT_REQUEST_BODY_LIMIT_BYTES, 1024 * 1024);
        let _layer = request_body_limit_default();
    }

    #[tokio::test]
    async fn security_headers_install_shared_baseline_without_overwriting_csp() {
        use tower::service_fn;
        use tower::ServiceExt;

        let service = security_headers(CspBuilder::restrictive()).layer(service_fn(
            |_request: Request<Body>| async {
                let mut response = Response::new(Body::empty());
                response.headers_mut().insert(
                    HeaderName::from_static("content-security-policy"),
                    HeaderValue::from_static("default-src 'none'"),
                );
                Ok::<_, std::convert::Infallible>(response)
            },
        ));

        let response = service
            .oneshot(Request::new(Body::empty()))
            .await
            .expect("security header service responds");
        let headers = response.headers();
        assert_eq!(
            headers.get("content-security-policy"),
            Some(&HeaderValue::from_static("default-src 'none'"))
        );
        assert_eq!(
            headers.get("x-content-type-options"),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            headers.get("referrer-policy"),
            Some(&HeaderValue::from_static("no-referrer"))
        );
        assert_eq!(
            headers.get("x-frame-options"),
            Some(&HeaderValue::from_static("DENY"))
        );
        assert_eq!(
            headers.get("permissions-policy"),
            Some(&HeaderValue::from_static(
                "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()"
            ))
        );
        assert_eq!(
            headers.get("cross-origin-opener-policy"),
            Some(&HeaderValue::from_static("same-origin"))
        );
        // HTTPSEC-01: HSTS is included in the default baseline.
        assert_eq!(
            headers.get("strict-transport-security"),
            Some(&HeaderValue::from_static(DEFAULT_HSTS_VALUE))
        );
    }

    // HTTPSEC-01: HSTS is present by default via security_headers().
    #[tokio::test]
    async fn security_headers_emits_hsts_by_default() {
        use tower::service_fn;
        use tower::ServiceExt;

        let service = security_headers(CspBuilder::restrictive()).layer(service_fn(
            |_request: Request<Body>| async {
                Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
            },
        ));
        let response = service
            .oneshot(Request::new(Body::empty()))
            .await
            .expect("service responds");
        assert_eq!(
            response.headers().get("strict-transport-security"),
            Some(&HeaderValue::from_static(DEFAULT_HSTS_VALUE)),
            "HSTS must be present by default"
        );
    }

    // HTTPSEC-01: without_hsts() opts out of the HSTS header.
    #[tokio::test]
    async fn security_headers_without_hsts_omits_hsts_header() {
        use tower::service_fn;
        use tower::ServiceExt;

        let service = security_headers(CspBuilder::restrictive())
            .without_hsts()
            .layer(service_fn(|_request: Request<Body>| async {
                Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
            }));
        let response = service
            .oneshot(Request::new(Body::empty()))
            .await
            .expect("service responds");
        assert!(
            response
                .headers()
                .get("strict-transport-security")
                .is_none(),
            "HSTS must be absent after without_hsts()"
        );
    }

    #[test]
    fn conditional_corp_matches_cors_response() {
        let mut response = Response::new(());
        apply_conditional_corp(&mut response);
        assert_eq!(
            response
                .headers()
                .get("cross-origin-resource-policy")
                .unwrap(),
            "same-origin"
        );

        response.headers_mut().insert(
            "access-control-allow-origin",
            HeaderValue::from_static("https://example.test"),
        );
        apply_conditional_corp(&mut response);
        assert_eq!(
            response
                .headers()
                .get("cross-origin-resource-policy")
                .unwrap(),
            "cross-origin"
        );
    }
}
