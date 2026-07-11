use super::*;

pub(in super::super) async fn oauth2_client_credentials_token(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    auth: &HttpJsonAuthConfig,
    credential: &Value,
) -> Result<String, SourceExecutionError> {
    let cache_key = oauth2_token_cache_key(source_id, auth)?;
    if let Some(token) = cached_oauth2_access_token(state, &cache_key).await {
        return Ok(token);
    }

    let fetch_lock = oauth2_token_fetch_lock(state, &cache_key).await;
    let _fetch_guard = fetch_lock.lock().await;
    if let Some(token) = cached_oauth2_access_token(state, &cache_key).await {
        return Ok(token);
    }

    let token_url = auth
        .token_url
        .as_deref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let token_url = reqwest::Url::parse(token_url).map_err(|_| SourceExecutionError::HttpJson)?;
    ensure_allowed_base_url(source_id, source, &token_url)
        .map_err(|_| SourceExecutionError::HttpJson)?;
    if token_url.fragment().is_some() {
        return Err(SourceExecutionError::HttpJson);
    }
    let client = http_json_client_for(state, source_id, source, &token_url).await?;
    let client_id_ref = auth
        .client_id
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let client_secret_ref = auth
        .client_secret
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let client_id = credential_secret(credential, client_id_ref)?;
    let client_secret = credential_secret(credential, client_secret_ref)?;
    let mut params = BTreeMap::new();
    params.insert("grant_type".to_string(), "client_credentials".to_string());
    params.insert("client_id".to_string(), client_id.to_string());
    params.insert("client_secret".to_string(), client_secret.to_string());
    if let Some(scope) = auth
        .scope
        .as_deref()
        .filter(|scope| !scope.trim().is_empty())
    {
        params.insert("scope".to_string(), scope.to_string());
    }
    if let Some(audience) = auth
        .audience
        .as_deref()
        .filter(|audience| !audience.trim().is_empty())
    {
        params.insert("audience".to_string(), audience.to_string());
    }

    let request = client
        .post(token_url.clone())
        .header(reqwest::header::ACCEPT, "application/json");
    let request = match oauth2_request_format(auth) {
        "json" => request.json(&params),
        "form" => request.form(&params),
        _ => return Err(SourceExecutionError::HttpJson),
    };
    let response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })?;
    if !response.status().is_success() {
        return Err(SourceExecutionError::HttpJson);
    }
    let body = read_limited_json_response(response, state.config.limits.max_output_bytes).await?;
    let access_token = body
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or(SourceExecutionError::HttpJson)?
        .to_string();
    let expires_in = body
        .get("expires_in")
        .and_then(oauth2_expires_in_seconds)
        .unwrap_or(300);
    let refresh_skew = Duration::from_secs(auth.refresh_skew_seconds.unwrap_or(60));
    let ttl = Duration::from_secs(expires_in);
    let refresh_after = Instant::now()
        + ttl
            .checked_sub(refresh_skew)
            .unwrap_or_else(|| Duration::from_secs(0));
    state.oauth2_tokens.lock().await.insert(
        cache_key,
        CachedOAuth2Token {
            access_token: access_token.clone(),
            refresh_after,
        },
    );
    Ok(access_token)
}

pub(in super::super) async fn cached_oauth2_access_token(
    state: &AppState,
    cache_key: &str,
) -> Option<String> {
    let now = Instant::now();
    state
        .oauth2_tokens
        .lock()
        .await
        .get(cache_key)
        .filter(|token| token.refresh_after > now)
        .map(|token| token.access_token.clone())
}

pub(in super::super) async fn oauth2_token_fetch_lock(
    state: &AppState,
    cache_key: &str,
) -> Arc<Mutex<()>> {
    let mut locks = state.oauth2_token_locks.lock().await;
    locks
        .entry(cache_key.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

pub(in super::super) fn oauth2_expires_in_seconds(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    }
}

pub(in super::super) fn oauth2_request_format(auth: &HttpJsonAuthConfig) -> &str {
    auth.request_format
        .as_deref()
        .filter(|format| !format.trim().is_empty())
        .unwrap_or("form")
}

pub(in super::super) fn oauth2_token_cache_key(
    source_id: &str,
    auth: &HttpJsonAuthConfig,
) -> Result<String, SourceExecutionError> {
    let token_url = auth
        .token_url
        .as_deref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let client_id_ref = auth
        .client_id
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let client_secret_ref = auth
        .client_secret
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let key = json!({
        "source_id": source_id,
        "token_url": token_url,
        "client_id_field": client_id_ref.secret.as_str(),
        "client_secret_field": client_secret_ref.secret.as_str(),
        "request_format": oauth2_request_format(auth),
        "scope": auth.scope.as_deref(),
        "audience": auth.audience.as_deref(),
    });
    let bytes = serde_json::to_vec(&key).map_err(|_| SourceExecutionError::HttpJson)?;
    Ok(registry_platform_config::sha256_uri(&bytes))
}

pub(in super::super) fn http_json_cache_key(
    state: &AppState,
    source_id: &str,
    request: &Value,
) -> Result<Option<String>, SourceExecutionError> {
    let Some(runtime) = state.source_runtime.get(source_id) else {
        return Err(SourceExecutionError::HttpJson);
    };
    let Some(source) = state.config.sources.get(source_id) else {
        return Err(SourceExecutionError::HttpJson);
    };
    if source.cache.is_none() {
        return Ok(None);
    }
    let key = json!({
        "source_config_hash": runtime.source_config_hash,
        "source_id": source_id,
        "dataset": request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": request.get("entity").cloned().unwrap_or(Value::Null),
        "lookup": request.get("lookup").cloned().unwrap_or(Value::Null),
        "fields": request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "limit": request.get("limit").cloned().unwrap_or(Value::Null),
        "purpose": request.get("purpose").cloned().unwrap_or(Value::Null),
    });
    let bytes = serde_json::to_vec(&key).map_err(|_| SourceExecutionError::HttpJson)?;
    Ok(Some(registry_platform_config::sha256_uri(&bytes)))
}

pub(in super::super) async fn http_json_cache_get(
    state: &AppState,
    source_id: &str,
    key: &str,
) -> Option<Value> {
    let runtime = state.source_runtime.get(source_id)?;
    let now = Instant::now();
    let mut cache = runtime.cache.lock().await;
    let entry = cache.get_mut(key)?;
    if entry.expires_at <= now {
        cache.remove(key);
        return None;
    }
    entry.last_accessed = now;
    let value = entry.value.clone();
    drop(cache);
    record_metric_with_items(state, source_id, "source_cache_hit", Duration::ZERO, 1).await;
    Some(value)
}

pub(in super::super) async fn http_json_cache_put(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    key: &str,
    records: &Value,
) {
    let Some(ttl_ms) = http_json_cache_ttl_ms(source, records) else {
        return;
    };
    let Some(runtime) = state.source_runtime.get(source_id) else {
        return;
    };
    let mut cache = runtime.cache.lock().await;
    let now = Instant::now();
    cache.retain(|_, entry| entry.expires_at > now);
    cache.insert(
        key.to_string(),
        CacheEntry {
            expires_at: now + Duration::from_millis(ttl_ms),
            last_accessed: now,
            value: records.clone(),
        },
    );
    evict_http_json_cache_entries(&mut cache, source.cache.as_ref());
}

pub(in super::super) fn http_json_cache_ttl_ms(
    source: &SourceConfig,
    records: &Value,
) -> Option<u64> {
    let cache = source.cache.as_ref()?;
    match records.as_array()?.len() {
        0 => cache.not_found_ttl_ms,
        1 => cache.exact_match_ttl_ms,
        _ => None,
    }
}

pub(in super::super) fn evict_http_json_cache_entries(
    cache: &mut BTreeMap<String, CacheEntry>,
    config: Option<&SourceCacheConfig>,
) {
    let max_entries = config
        .and_then(|cache| cache.max_entries)
        .unwrap_or(DEFAULT_SOURCE_CACHE_MAX_ENTRIES);
    if cache.len() <= max_entries {
        return;
    }
    let mut entries = cache
        .iter()
        .map(|(key, entry)| (key.clone(), entry.last_accessed))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(_, last_accessed)| *last_accessed);
    for (key, _) in entries.into_iter().take(cache.len() - max_entries) {
        cache.remove(&key);
    }
}
