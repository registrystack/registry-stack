use super::*;

mod oauth_cache;

pub(super) use oauth_cache::*;

pub(super) fn resolve_fhir_bearer_tokens(
    config: &SidecarConfig,
) -> Result<BTreeMap<String, String>, SidecarError> {
    let mut tokens = BTreeMap::new();
    for (source_id, source) in &config.sources {
        if source.engine != SourceEngine::Fhir {
            continue;
        }
        let Some(env) = source
            .fhir
            .as_ref()
            .and_then(|fhir| fhir.bearer_token_env.as_ref())
        else {
            continue;
        };
        if tokens.contains_key(env) {
            continue;
        }
        let token = std::env::var(env).ok().filter(|token| !token.is_empty());
        let Some(token) = token else {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir.bearer_token_env {env} is missing or empty"
            )));
        };
        tokens.insert(env.clone(), token);
    }
    Ok(tokens)
}

pub(super) fn apply_fhir_auth(
    state: &AppState,
    fhir: &FhirSourceConfig,
    mut builder: reqwest::RequestBuilder,
) -> Result<reqwest::RequestBuilder, SourceExecutionError> {
    if let Some(env) = &fhir.bearer_token_env {
        let token = state
            .fhir_bearer_tokens
            .get(env)
            .ok_or(SourceExecutionError::HttpJson)?;
        builder = builder.bearer_auth(token);
    }
    Ok(builder)
}

pub(super) fn credential_secret<'a>(
    credential: &'a Value,
    secret_ref: &HttpJsonSecretRef,
) -> Result<&'a str, SourceExecutionError> {
    credential
        .get(&secret_ref.secret)
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)
}

pub(super) async fn apply_http_json_auth(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    mut builder: reqwest::RequestBuilder,
    auth: Option<&HttpJsonAuthConfig>,
    credential: &Value,
) -> Result<reqwest::RequestBuilder, SourceExecutionError> {
    if let Some(auth) = auth {
        match auth.kind {
            HttpJsonAuthKind::Bearer => {
                let token_ref = auth.token.as_ref().ok_or(SourceExecutionError::HttpJson)?;
                let token = credential_secret(credential, token_ref)?;
                builder = builder.bearer_auth(token);
            }
            HttpJsonAuthKind::Basic => {
                let username_ref = auth
                    .username
                    .as_ref()
                    .ok_or(SourceExecutionError::HttpJson)?;
                let password_ref = auth
                    .password
                    .as_ref()
                    .ok_or(SourceExecutionError::HttpJson)?;
                let username = credential_secret(credential, username_ref)?;
                let password = credential_secret(credential, password_ref)?;
                builder = builder.basic_auth(username, Some(password));
            }
            HttpJsonAuthKind::ApiKeyHeader => {
                // Header name and secret-field name are config-validated at
                // startup; the resolved value is the secret, never logged.
                let header = auth
                    .header
                    .as_deref()
                    .ok_or(SourceExecutionError::HttpJson)?;
                let token_ref = auth.token.as_ref().ok_or(SourceExecutionError::HttpJson)?;
                let token = credential_secret(credential, token_ref)?;
                builder = builder.header(header, token);
            }
            HttpJsonAuthKind::ApiKeyQuery => {
                // reqwest percent-encodes and appends the parameter. The cache
                // key is built from request fields (not the URL), and the URL is
                // never logged, so the secret does not leak via either path.
                let param = auth
                    .query_param
                    .as_deref()
                    .ok_or(SourceExecutionError::HttpJson)?;
                let token_ref = auth.token.as_ref().ok_or(SourceExecutionError::HttpJson)?;
                let token = credential_secret(credential, token_ref)?;
                builder = builder.query(&[(param, token)]);
            }
            HttpJsonAuthKind::OAuth2ClientCredentials => {
                let token =
                    oauth2_client_credentials_token(state, source_id, source, auth, credential)
                        .await?;
                builder = builder.bearer_auth(token);
            }
        }
    }
    Ok(builder)
}

pub(super) async fn read_limited_json_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Value, SourceExecutionError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })? {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(SourceExecutionError::HttpJson);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| SourceExecutionError::HttpJson)
}

pub(super) async fn read_limited_json_or_empty_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Value, SourceExecutionError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })? {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(SourceExecutionError::HttpJson);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&bytes).map_err(|_| SourceExecutionError::HttpJson)
}

pub(super) async fn read_limited_optional_json_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Value, SourceExecutionError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })? {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Ok(Value::Null);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

pub(super) async fn prepare_http_json_request(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    base_url: &str,
    path: &str,
) -> Result<PreparedHttpJsonRequest, SourceExecutionError> {
    let base = reqwest::Url::parse(base_url).map_err(|_| SourceExecutionError::HttpJson)?;
    ensure_allowed_base_url(source_id, source, &base)
        .map_err(|_| SourceExecutionError::HttpJson)?;
    let url = append_http_json_path(&base, path).map_err(|_| SourceExecutionError::HttpJson)?;
    ensure_same_origin(&base, &url).map_err(|_| SourceExecutionError::HttpJson)?;
    let client = http_json_client_for(state, source_id, source, &base).await?;
    Ok(PreparedHttpJsonRequest { url, client })
}

pub(super) async fn http_json_client_for(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    base: &reqwest::Url,
) -> Result<reqwest::Client, SourceExecutionError> {
    let cache_key = format!("{}|{}", source_id, base.as_str().trim_end_matches('/'));
    if let Some(client) = state
        .http_json_clients
        .lock()
        .await
        .get(&cache_key)
        .cloned()
    {
        return Ok(client);
    }

    let resolved_addrs = ensure_http_json_url_policy(base, source)
        .await
        .map_err(|_| SourceExecutionError::HttpJson)?;
    let host = base
        .host_str()
        .ok_or(SourceExecutionError::HttpJson)?
        .to_string();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(state.config.limits.worker_timeout_ms))
        .resolve_to_addrs(&host, &resolved_addrs)
        .build()
        .map_err(|_| SourceExecutionError::HttpJson)?;
    let mut clients = state.http_json_clients.lock().await;
    let client = clients.entry(cache_key).or_insert(client).clone();
    Ok(client)
}

pub(super) fn append_http_json_path(base: &reqwest::Url, path: &str) -> Result<reqwest::Url, ()> {
    if path.starts_with("//") {
        return Err(());
    }
    let suffix = path.trim_start_matches('/');
    if suffix
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(());
    }
    let base_path = base.path().trim_end_matches('/');
    let combined_path = if base_path.is_empty() || base_path == "/" {
        format!("/{suffix}")
    } else if suffix.is_empty() {
        base_path.to_string()
    } else {
        format!("{base_path}/{suffix}")
    };
    let mut url = base.clone();
    url.set_path(&combined_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

pub(super) fn ensure_allowed_base_url(
    source_id: &str,
    source: &SourceConfig,
    base_url: &reqwest::Url,
) -> Result<(), SidecarError> {
    let normalized = base_url.as_str().trim_end_matches('/');
    if source
        .allowed_base_urls
        .iter()
        .map(|allowed| allowed.trim_end_matches('/'))
        .any(|allowed| allowed == normalized)
    {
        Ok(())
    } else {
        Err(SidecarError::Config(format!(
            "source {source_id} http_json base_url is not in allowed_base_urls"
        )))
    }
}

pub(super) fn ensure_same_origin(base: &reqwest::Url, url: &reqwest::Url) -> Result<(), ()> {
    if base.scheme() == url.scheme()
        && base.host_str() == url.host_str()
        && base.port_or_known_default() == url.port_or_known_default()
    {
        Ok(())
    } else {
        Err(())
    }
}

pub(super) async fn ensure_http_json_url_policy(
    url: &reqwest::Url,
    source: &SourceConfig,
) -> Result<Vec<SocketAddr>, ()> {
    let Some(host) = url.host_str() else {
        return Err(());
    };
    let port = url.port_or_known_default().ok_or(())?;
    if url.scheme() != "https" {
        if url.scheme() != "http" {
            return Err(());
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            ensure_ip_allowed(ip, source)?;
            if !ip.is_loopback() && !is_private_or_link_local_ip(ip) {
                return Err(());
            }
            return Ok(vec![SocketAddr::new(ip, port)]);
        } else if is_localhost_host(host) {
            if !source.allow_insecure_localhost {
                return Err(());
            }
        } else if !source.allow_insecure_private_network {
            return Err(());
        } else {
            // Resolve below and allow only private/link-local addresses for
            // plain HTTP service names.
        }
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        ensure_ip_allowed(ip, source)?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if is_localhost_host(host) {
        if source.allow_insecure_localhost || source.allow_insecure_private_network {
            return Ok(vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)]);
        }
        return Err(());
    }
    let mut resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| ())?;
    let mut addrs = Vec::new();
    for address in &mut resolved {
        let ip = canonical_ip(address.ip());
        ensure_ip_allowed(ip, source)?;
        if url.scheme() == "http" && !ip.is_loopback() && !is_private_or_link_local_ip(ip) {
            return Err(());
        }
        addrs.push(address);
    }
    if addrs.is_empty() {
        return Err(());
    }
    Ok(addrs)
}

pub(super) fn ensure_ip_allowed(ip: IpAddr, source: &SourceConfig) -> Result<(), ()> {
    let ip = canonical_ip(ip);
    if is_cloud_metadata_ip(ip) {
        return Err(());
    }
    if ip.is_loopback() {
        return if source.allow_insecure_localhost || source.allow_insecure_private_network {
            Ok(())
        } else {
            Err(())
        };
    }
    if is_private_or_link_local_ip(ip) {
        return if source.allow_insecure_private_network {
            Ok(())
        } else {
            Err(())
        };
    }
    Ok(())
}

pub(super) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(_) => ip,
    }
}

pub(super) fn is_localhost_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub(super) fn is_private_or_link_local_ip(ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast()
        }
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local() || ip.is_unspecified(),
    }
}

pub(super) fn load_credentials(
    config: &SidecarConfig,
) -> Result<BTreeMap<String, Value>, SidecarError> {
    let mut credentials = BTreeMap::new();
    for (source_id, source) in &config.sources {
        if source.credential_env.trim().is_empty() {
            continue;
        }
        let raw =
            std::env::var(&source.credential_env).map_err(|_| SidecarError::MissingCredential {
                source_id: source_id.clone(),
                env: source.credential_env.clone(),
            })?;
        let credential =
            serde_json::from_str(&raw).map_err(|error| SidecarError::CredentialJson {
                source_id: source_id.clone(),
                env: source.credential_env.clone(),
                source: error,
            })?;
        // The single-`baseUrl` credential gate is an http_json/http_flow/fhir
        // shape. A `script_rhai` source binds its upstreams per-target via
        // `rhai.targets[*].base_url` (each validated against `allowed_base_urls`
        // up front), so it has no one credential `baseUrl` to pin here.
        if source.engine != SourceEngine::ScriptRhai {
            validate_credential_base_url(source_id, source, &credential)?;
        }
        credentials.insert(source_id.clone(), credential);
    }
    Ok(credentials)
}

pub(super) fn validate_credential_base_url(
    source_id: &str,
    source: &SourceConfig,
    credential: &Value,
) -> Result<(), SidecarError> {
    if source.allowed_base_urls.is_empty() {
        return Ok(());
    }
    let Some(base_url) = credential.get("baseUrl").and_then(Value::as_str) else {
        return Err(SidecarError::CredentialBaseUrl {
            source_id: source_id.to_string(),
            env: source.credential_env.clone(),
        });
    };
    let normalized = base_url.trim_end_matches('/');
    if source
        .allowed_base_urls
        .iter()
        .map(|allowed| allowed.trim_end_matches('/'))
        .any(|allowed| allowed == normalized)
    {
        Ok(())
    } else {
        Err(SidecarError::CredentialBaseUrl {
            source_id: source_id.to_string(),
            env: source.credential_env.clone(),
        })
    }
}
