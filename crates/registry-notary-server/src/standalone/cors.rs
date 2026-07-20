use super::*;

#[derive(Debug, Clone)]
pub(super) struct SubjectAccessWalletCorsPolicy {
    enabled: bool,
    allowed_origins: Vec<String>,
    allow_credentials: bool,
}

impl SubjectAccessWalletCorsPolicy {
    pub(super) fn from_config(config: &StandaloneRegistryNotaryConfig) -> Self {
        Self {
            enabled: config.subject_access.enabled,
            allowed_origins: config.subject_access.allowed_wallet_origins.clone(),
            allow_credentials: false,
        }
    }

    fn allows_origin(&self, origin: &str) -> bool {
        self.allowed_origins
            .iter()
            .any(|allowed| allowed.as_str() == origin)
    }
}

pub(super) async fn subject_access_wallet_cors_middleware(
    State(policy): State<SubjectAccessWalletCorsPolicy>,
    request: Request,
    next: Next,
) -> Response {
    if !policy.enabled || !is_subject_access_wallet_cors_path(request.uri().path()) {
        return next.run(request).await;
    }

    let origin = request.headers().get(header::ORIGIN).cloned();
    let Some(origin) = origin else {
        return next.run(request).await;
    };
    let origin_allowed = origin
        .to_str()
        .is_ok_and(|origin| policy.allows_origin(origin));
    let requested_headers = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .cloned();
    let is_preflight = request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);

    if is_preflight {
        let mut response = StatusCode::NO_CONTENT.into_response();
        if origin_allowed {
            apply_subject_access_wallet_cors_headers(
                response.headers_mut(),
                origin,
                requested_headers.as_ref(),
                policy.allow_credentials,
            );
        }
        return response;
    }

    let mut response = next.run(request).await;
    if origin_allowed {
        apply_subject_access_wallet_cors_headers(
            response.headers_mut(),
            origin,
            requested_headers.as_ref(),
            policy.allow_credentials,
        );
    } else {
        remove_access_control_headers(response.headers_mut());
    }
    response
}

pub(super) fn is_subject_access_wallet_cors_path(path: &str) -> bool {
    matches!(
        path,
        "/.well-known/evidence-service"
            | "/.well-known/evidence/jwks.json"
            | "/.well-known/openid-credential-issuer"
            | "/oid4vci/credential"
            | "/v1/formats"
            | "/v1/evaluations"
            | "/v1/batch-evaluations"
            | "/v1/credentials"
    ) || path == "/v1/claims"
        || path.starts_with("/v1/claims/")
        || path == "/credentials/{*vct_path}"
        || path.starts_with("/credentials/")
        || path.starts_with("/.well-known/vct/")
        || path.starts_with("/v1/evaluations/")
        || path.starts_with("/v1/credentials/")
}

fn apply_subject_access_wallet_cors_headers(
    headers: &mut HeaderMap,
    origin: HeaderValue,
    requested_headers: Option<&HeaderValue>,
    allow_credentials: bool,
) {
    remove_access_control_headers(headers);
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(SELF_ATTESTATION_CORS_METHODS),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        requested_headers
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static(SELF_ATTESTATION_CORS_DEFAULT_HEADERS)),
    );
    if allow_credentials {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    headers.insert(
        header::VARY,
        HeaderValue::from_static(
            "origin, access-control-request-method, access-control-request-headers",
        ),
    );
}

fn remove_access_control_headers(headers: &mut HeaderMap) {
    headers.remove(header::ACCESS_CONTROL_ALLOW_ORIGIN);
    headers.remove(header::ACCESS_CONTROL_ALLOW_METHODS);
    headers.remove(header::ACCESS_CONTROL_ALLOW_HEADERS);
    headers.remove(header::ACCESS_CONTROL_ALLOW_CREDENTIALS);
}
