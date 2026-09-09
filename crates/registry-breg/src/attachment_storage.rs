// SPDX-License-Identifier: Apache-2.0
//! Deployment-bound S3 content storage. PostgreSQL owns references, locking,
//! pending writes and durable deletion retries; this adapter owns only bytes.

use std::{fmt, net::IpAddr, sync::Arc, time::Duration};

use hmac::{Hmac, KeyInit, Mac};
use quick_xml::{events::Event, Reader};
use registry_platform_config::{ProtectedSecret, SecretReference, SecretResolver};
use registry_platform_httputil::{read_bounded, validate_response_headers, OutboundClientBuilder};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Method, StatusCode, Url,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const MAXIMUM_BLOB_BYTES: u64 = crate::contract::MAX_ATTACHMENT_BYTES as u64;
const MAXIMUM_CONTROL_BYTES: u64 = 16 * 1024;

/// Storage failures carry no URLs, object keys, credentials or backend responses.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AttachmentStorageError {
    #[error("attachment storage configuration is invalid")]
    InvalidConfiguration,
    #[error("attachment storage secret resolution failed")]
    Secret,
    #[error("attachment storage is unavailable")]
    Unavailable,
    #[error("attachment content is unavailable")]
    Missing,
    #[error("attachment content failed integrity validation")]
    Integrity,
    #[error("attachment storage requires a bucket that has never enabled versioning")]
    VersionedBucket,
}

type Result<T> = std::result::Result<T, AttachmentStorageError>;

/// Omitted configuration selects transactional PostgreSQL content storage.
#[derive(Clone, Default)]
pub enum AttachmentStorage {
    #[default]
    Database,
    S3(Arc<S3AttachmentStore>),
}

impl AttachmentStorage {
    /// Persist beside retained content; a changed binding cannot read/delete it.
    pub fn binding_digest(&self) -> String {
        match self {
            Self::Database => "database".to_string(),
            Self::S3(store) => store.binding_digest.clone(),
        }
    }
}

impl fmt::Debug for AttachmentStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Database => "AttachmentStorage::Database",
            Self::S3(_) => "AttachmentStorage::S3(<redacted>)",
        })
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum RawAttachmentStorageConfig {
    Database {},
    S3 {
        #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 2048)))]
        endpoint: String,
        #[cfg_attr(feature = "schema", schemars(length(min = 3, max = 63)))]
        bucket: String,
        #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 64)))]
        region: String,
        #[serde(default = "default_path_style")]
        path_style: bool,
        access_key_id_ref: String,
        secret_access_key_ref: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token_ref: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca_bundle_ref: Option<String>,
        #[serde(default = "default_timeout")]
        #[cfg_attr(feature = "schema", schemars(range(min = 100, max = 60_000)))]
        timeout_milliseconds: u64,
    },
}

impl Default for RawAttachmentStorageConfig {
    fn default() -> Self {
        Self::Database {}
    }
}

fn default_path_style() -> bool {
    true
}
fn default_timeout() -> u64 {
    10_000
}

/// Validated deployment settings. Debug never reveals deployment values.
#[derive(Clone, Default)]
pub(crate) struct AttachmentStorageConfig(Option<S3Config>);

#[derive(Clone)]
struct S3Config {
    bucket_url: Url,
    region: String,
    access_key_id_ref: SecretReference,
    secret_access_key_ref: SecretReference,
    session_token_ref: Option<SecretReference>,
    ca_bundle_ref: Option<SecretReference>,
    timeout: Duration,
}

impl AttachmentStorageConfig {
    pub(crate) fn from_raw(raw: RawAttachmentStorageConfig) -> Result<Self> {
        let RawAttachmentStorageConfig::S3 {
            endpoint,
            bucket,
            region,
            path_style,
            access_key_id_ref,
            secret_access_key_ref,
            session_token_ref,
            ca_bundle_ref,
            timeout_milliseconds,
        } = raw
        else {
            return Ok(Self::default());
        };
        let mut url =
            Url::parse(&endpoint).map_err(|_| AttachmentStorageError::InvalidConfiguration)?;
        let loopback = url
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if endpoint.len() > 2048
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.host_str().is_none()
            || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || !(3..=63).contains(&bucket.len())
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
            || !bucket.as_bytes()[0].is_ascii_alphanumeric()
            || !bucket.as_bytes()[bucket.len() - 1].is_ascii_alphanumeric()
            || bucket.contains("..")
            || bucket.parse::<IpAddr>().is_ok()
            || region.is_empty()
            || region.len() > 64
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !(100..=60_000).contains(&timeout_milliseconds)
        {
            return Err(AttachmentStorageError::InvalidConfiguration);
        }
        if path_style {
            url.set_path(&format!("/{bucket}"));
        } else {
            if url
                .host_str()
                .is_none_or(|host| host.parse::<IpAddr>().is_ok() || host.contains(':'))
            {
                return Err(AttachmentStorageError::InvalidConfiguration);
            }
            url.set_host(Some(&format!(
                "{bucket}.{}",
                url.host_str().unwrap_or_default()
            )))
            .map_err(|_| AttachmentStorageError::InvalidConfiguration)?;
        }
        let secret = |value| {
            SecretReference::parse(value).map_err(|_| AttachmentStorageError::InvalidConfiguration)
        };
        Ok(Self(Some(S3Config {
            bucket_url: url,
            region,
            access_key_id_ref: secret(access_key_id_ref)?,
            secret_access_key_ref: secret(secret_access_key_ref)?,
            session_token_ref: session_token_ref.map(secret).transpose()?,
            ca_bundle_ref: ca_bundle_ref.map(secret).transpose()?,
            timeout: Duration::from_millis(timeout_milliseconds),
        })))
    }

    pub(crate) async fn activate(
        &self,
        registry_id: &str,
        resolver: &SecretResolver,
    ) -> Result<AttachmentStorage> {
        let Some(config) = &self.0 else {
            return Ok(AttachmentStorage::Database);
        };
        if registry_id.is_empty() || registry_id.len() > 1024 {
            return Err(AttachmentStorageError::InvalidConfiguration);
        }
        let resolve = |reference: &SecretReference| {
            resolver
                .resolve_reference(reference)
                .map_err(|_| AttachmentStorageError::Secret)
        };
        let access_key_id = resolve(&config.access_key_id_ref)?;
        let secret_access_key = resolve(&config.secret_access_key_ref)?;
        let session_token = config.session_token_ref.as_ref().map(resolve).transpose()?;
        for secret in [&access_key_id, &secret_access_key]
            .into_iter()
            .chain(session_token.iter())
        {
            if secret.is_empty()
                || secret.len() > 4096
                || !secret.expose_secret().iter().all(|b| b.is_ascii_graphic())
            {
                return Err(AttachmentStorageError::Secret);
            }
        }
        if !access_key_id
            .expose_secret()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return Err(AttachmentStorageError::Secret);
        }
        let mut builder = OutboundClientBuilder::new()
            .timeout(config.timeout)
            .connect_timeout(config.timeout.min(Duration::from_secs(5)));
        if let Some(reference) = &config.ca_bundle_ref {
            builder =
                builder.trusted_root_certificates(resolve(reference)?.expose_secret().to_vec());
        }
        let scope = hex::encode(Sha256::digest(registry_id.as_bytes()));
        let identity = serde_json::to_vec(&(
            "breg-attachment-s3-v1",
            config.bucket_url.as_str(),
            &config.region,
            &scope,
        ))
        .map_err(|_| AttachmentStorageError::InvalidConfiguration)?;
        let store = S3AttachmentStore {
            client: builder
                .try_build()
                .map_err(|_| AttachmentStorageError::InvalidConfiguration)?,
            bucket_url: config.bucket_url.clone(),
            region: config.region.clone(),
            scope,
            access_key_id,
            secret_access_key,
            session_token,
            binding_digest: hex::encode(Sha256::digest(identity)),
        };
        store.ensure_unversioned().await?;
        Ok(AttachmentStorage::S3(Arc::new(store)))
    }
}

impl fmt::Debug for AttachmentStorageConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() {
            "AttachmentStorageConfig::S3(<redacted>)"
        } else {
            "AttachmentStorageConfig::Database"
        })
    }
}

/// Bounded SigV4 S3 operations, confined to one bucket and Registry hash prefix.
/// Callers must hold their database content lock through each mutating operation.
/// No automatic retries occur: uncertain writes/deletes are reconciled by the
/// caller's durable pending-operation records using the same deterministic key.
pub struct S3AttachmentStore {
    client: reqwest::Client,
    bucket_url: Url,
    region: String,
    scope: String,
    access_key_id: ProtectedSecret,
    secret_access_key: ProtectedSecret,
    session_token: Option<ProtectedSecret>,
    binding_digest: String,
}

impl fmt::Debug for S3AttachmentStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("S3AttachmentStore(<redacted>)")
    }
}

impl S3AttachmentStore {
    fn object_url(&self, sha256: &str) -> Result<Url> {
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(AttachmentStorageError::Integrity);
        }
        let mut url = self.bucket_url.clone();
        let path = format!(
            "{}/breg/{}/{sha256}",
            url.path().trim_end_matches('/'),
            self.scope
        );
        url.set_path(&path);
        Ok(url)
    }

    pub async fn put(&self, sha256: &str, bytes: Vec<u8>) -> Result<()> {
        let url = self.object_url(sha256)?;
        verify_content(sha256, bytes.len() as u64, &bytes)?;
        self.ensure_unversioned().await?;
        let size = bytes.len() as u64;
        let response = self.send(Method::PUT, url, bytes).await?;
        require_success(&response)?;
        require_unversioned_headers(response.headers())?;
        read_bounded(response, MAXIMUM_CONTROL_BYTES)
            .await
            .map_err(|_| AttachmentStorageError::Unavailable)?;
        self.get(sha256, size).await?;
        Ok(())
    }

    pub async fn get(&self, sha256: &str, expected_size: u64) -> Result<Vec<u8>> {
        if expected_size > MAXIMUM_BLOB_BYTES {
            return Err(AttachmentStorageError::Integrity);
        }
        let response = self
            .send(Method::GET, self.object_url(sha256)?, Vec::new())
            .await?;
        require_success(&response)?;
        require_unversioned_headers(response.headers())?;
        let bytes = read_bounded(response, expected_size)
            .await
            .map_err(|_| AttachmentStorageError::Integrity)?;
        verify_content(sha256, expected_size, &bytes)?;
        Ok(bytes)
    }

    /// Success means the service confirmed deletion and a subsequent GET is 404.
    /// Buckets with versioning enabled or suspended are deliberately unsupported.
    pub async fn delete(&self, sha256: &str) -> Result<()> {
        let url = self.object_url(sha256)?;
        self.ensure_unversioned().await?;
        let response = self.send(Method::DELETE, url.clone(), Vec::new()).await?;
        require_success(&response)?;
        require_unversioned_headers(response.headers())?;
        read_bounded(response, MAXIMUM_CONTROL_BYTES)
            .await
            .map_err(|_| AttachmentStorageError::Unavailable)?;
        self.ensure_unversioned().await?;
        let response = self.send(Method::GET, url, Vec::new()).await?;
        require_unversioned_headers(response.headers())?;
        if response.status() != StatusCode::NOT_FOUND {
            return Err(AttachmentStorageError::Unavailable);
        }
        Ok(())
    }

    async fn ensure_unversioned(&self) -> Result<()> {
        let mut url = self.bucket_url.clone();
        url.set_query(Some("versioning="));
        let response = self.send(Method::GET, url, Vec::new()).await?;
        require_success(&response)?;
        let bytes = read_bounded(response, MAXIMUM_CONTROL_BYTES)
            .await
            .map_err(|_| AttachmentStorageError::Unavailable)?;
        validate_unversioned_xml(&bytes)
    }

    async fn send(&self, method: Method, url: Url, body: Vec<u8>) -> Result<reqwest::Response> {
        let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = self.signed_headers(&method, &url, &body, &timestamp)?;
        let response = self
            .client
            .request(method, url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|_| AttachmentStorageError::Unavailable)?;
        validate_response_headers(response.headers())
            .map_err(|_| AttachmentStorageError::Unavailable)?;
        Ok(response)
    }

    fn signed_headers(
        &self,
        method: &Method,
        url: &Url,
        body: &[u8],
        timestamp: &str,
    ) -> Result<HeaderMap> {
        let host = url
            .host_str()
            .ok_or(AttachmentStorageError::InvalidConfiguration)?;
        let host = url
            .port()
            .map_or_else(|| host.to_string(), |port| format!("{host}:{port}"));
        let payload_hash = hex::encode(Sha256::digest(body));
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("host", host.as_str()),
            ("x-amz-content-sha256", payload_hash.as_str()),
            ("x-amz-date", timestamp),
        ] {
            headers.insert(
                name,
                HeaderValue::from_str(value)
                    .map_err(|_| AttachmentStorageError::InvalidConfiguration)?,
            );
        }
        if let Some(token) = &self.session_token {
            let mut value = HeaderValue::from_bytes(token.expose_secret())
                .map_err(|_| AttachmentStorageError::Secret)?;
            value.set_sensitive(true);
            headers.insert("x-amz-security-token", value);
        }
        let mut names = headers.keys().map(|key| key.as_str()).collect::<Vec<_>>();
        names.sort_unstable();
        let signed_names = names.join(";");
        let mut canonical_headers = Zeroizing::new(String::new());
        for name in names {
            canonical_headers.push_str(name);
            canonical_headers.push(':');
            canonical_headers.push_str(
                headers[name]
                    .to_str()
                    .map_err(|_| AttachmentStorageError::Secret)?,
            );
            canonical_headers.push('\n');
        }
        let canonical = Zeroizing::new(format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            url.path(),
            url.query().unwrap_or_default(),
            canonical_headers.as_str(),
            signed_names,
            payload_hash
        ));
        let date = &timestamp[..8];
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let mut prefixed = Zeroizing::new(b"AWS4".to_vec());
        prefixed.extend_from_slice(self.secret_access_key.expose_secret());
        let date_key = hmac(&prefixed, date.as_bytes());
        let region_key = hmac(&date_key, self.region.as_bytes());
        let service_key = hmac(&region_key, b"s3");
        let signing_key = hmac(&service_key, b"aws4_request");
        let signature = hex::encode(hmac(&signing_key, to_sign.as_bytes()).as_slice());
        let access_key_id = std::str::from_utf8(self.access_key_id.expose_secret())
            .map_err(|_| AttachmentStorageError::Secret)?;
        let authorization = Zeroizing::new(format!("AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={signed_names}, Signature={signature}"));
        let mut value =
            HeaderValue::from_str(&authorization).map_err(|_| AttachmentStorageError::Secret)?;
        value.set_sensitive(true);
        headers.insert("authorization", value);
        Ok(headers)
    }
}

fn hmac(key: &[u8], value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(value);
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

fn verify_content(sha256: &str, expected_size: u64, bytes: &[u8]) -> Result<()> {
    if expected_size > MAXIMUM_BLOB_BYTES
        || bytes.len() as u64 != expected_size
        || hex::encode(Sha256::digest(bytes)) != sha256
    {
        return Err(AttachmentStorageError::Integrity);
    }
    Ok(())
}

fn require_success(response: &reqwest::Response) -> Result<()> {
    if response.status() == StatusCode::NOT_FOUND {
        return Err(AttachmentStorageError::Missing);
    }
    if !response.status().is_success() {
        return Err(AttachmentStorageError::Unavailable);
    }
    Ok(())
}

fn require_unversioned_headers(headers: &HeaderMap) -> Result<()> {
    if headers
        .get_all("x-amz-version-id")
        .iter()
        .any(|value| value != "null")
        || headers.contains_key("x-amz-delete-marker")
    {
        return Err(AttachmentStorageError::VersionedBucket);
    }
    Ok(())
}

fn validate_unversioned_xml(bytes: &[u8]) -> Result<()> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut root = false;
    let mut closed = false;
    loop {
        match reader
            .read_event()
            .map_err(|_| AttachmentStorageError::Unavailable)?
        {
            Event::Decl(_) | Event::Comment(_) => {}
            Event::Start(element)
                if !root && element.local_name().as_ref() == "VersioningConfiguration" =>
            {
                root = true
            }
            Event::Empty(element)
                if !root && element.local_name().as_ref() == "VersioningConfiguration" =>
            {
                root = true;
                closed = true;
            }
            Event::End(element)
                if root
                    && !closed
                    && element.local_name().as_ref() == "VersioningConfiguration" =>
            {
                closed = true
            }
            Event::Eof if root && closed => return Ok(()),
            Event::Start(element) | Event::Empty(element)
                if element.local_name().as_ref() == "Status" =>
            {
                return Err(AttachmentStorageError::VersionedBucket)
            }
            _ => return Err(AttachmentStorageError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_config::SecretProvider;
    use serde_json::json;

    struct SecretFiles(std::path::PathBuf);
    impl SecretFiles {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("breg-s3-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            for (name, value) in [
                ("access", "breg960test"),
                ("secret", "breg960-test-only-secret"),
            ] {
                let path = root.join(name);
                std::fs::write(&path, value).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            Self(root)
        }
        fn resolver(&self) -> SecretResolver {
            SecretResolver::new([SecretProvider::File], &self.0).unwrap()
        }
    }
    impl Drop for SecretFiles {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn raw(endpoint: &str) -> serde_json::Value {
        json!({"kind":"s3", "endpoint":endpoint, "bucket":"breg-960-test", "region":"us-east-1", "accessKeyIdRef":"secret:file/access", "secretAccessKeyRef":"secret:file/secret"})
    }

    fn store(endpoint: &str, scope: &str) -> S3AttachmentStore {
        let files = SecretFiles::new();
        let resolver = files.resolver();
        let config =
            AttachmentStorageConfig::from_raw(serde_json::from_value(raw(endpoint)).unwrap())
                .unwrap()
                .0
                .unwrap();
        S3AttachmentStore {
            client: OutboundClientBuilder::new()
                .timeout(Duration::from_secs(2))
                .try_build()
                .unwrap(),
            bucket_url: config.bucket_url,
            region: config.region,
            scope: hex::encode(Sha256::digest(scope)),
            access_key_id: resolver
                .resolve_reference(&config.access_key_id_ref)
                .unwrap(),
            secret_access_key: resolver
                .resolve_reference(&config.secret_access_key_ref)
                .unwrap(),
            session_token: None,
            binding_digest: "test".to_string(),
        }
    }

    #[test]
    fn ipv6_signed_host_preserves_brackets_and_normalizes_default_ports() {
        // Generated independently with Python hashlib/hmac using the explicitly
        // bracketed canonical Host, empty payload, and fixed timestamp below.
        for (endpoint, expected_host, signature) in [
            (
                "http://[::1]",
                "[::1]",
                "0ee10b0dc41c4bff26a5dd9eaad63941772aae90d96c7019fce39cd81cd52150",
            ),
            (
                "http://[::1]:80",
                "[::1]",
                "0ee10b0dc41c4bff26a5dd9eaad63941772aae90d96c7019fce39cd81cd52150",
            ),
            (
                "http://[::1]:9000",
                "[::1]:9000",
                "36ddf894e9015041c902f6634914112167bb44b846e701ae807a5d165eebb194",
            ),
            (
                "https://[2001:db8::1]",
                "[2001:db8::1]",
                "950e3a5899c2224bca023a1c0718c2d55c967c90da7bdd03a8b3ac32e97d369e",
            ),
            (
                "https://[2001:db8::1]:443",
                "[2001:db8::1]",
                "950e3a5899c2224bca023a1c0718c2d55c967c90da7bdd03a8b3ac32e97d369e",
            ),
            (
                "https://[2001:db8::1]:9443",
                "[2001:db8::1]:9443",
                "7457aafa835bafa86bae6674c427198ac240c89b22488b2907c3ce60f7c885c1",
            ),
        ] {
            let store = store(endpoint, "registry");
            let mut url = store.bucket_url.clone();
            url.set_query(Some("versioning="));
            let parsed_host = url.host_str().unwrap();
            assert!(parsed_host.starts_with('[') && parsed_host.ends_with(']'));
            let headers = store
                .signed_headers(&Method::GET, &url, &[], "20260909T120000Z")
                .unwrap();
            assert_eq!(headers["host"], expected_host);
            let expected_authorization = format!("AWS4-HMAC-SHA256 Credential=breg960test/20260909/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}");
            assert_eq!(headers["authorization"], expected_authorization);
            let request = store.client.get(url).headers(headers).build().unwrap();
            assert_eq!(request.headers()["host"], expected_host);
        }
    }

    #[tokio::test]
    async fn ipv6_signed_request_preserves_bracketed_host_on_wire() {
        use axum::{extract::Request, routing::get, Router};
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let expected_host = address.to_string();
        let received = Arc::new(AtomicBool::new(false));
        let observed = received.clone();
        let app = Router::new().route(
            "/breg-960-test",
            get(move |request: Request| {
                let expected_host = expected_host.clone();
                let observed = observed.clone();
                async move {
                    let host_matches = request
                        .headers()
                        .get("host")
                        .is_some_and(|value| value == expected_host.as_str());
                    let host_is_signed = request
                        .headers()
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|value| {
                            value.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date,")
                        });
                    let exact_request = host_matches
                        && host_is_signed
                        && request.uri().query() == Some("versioning=");
                    observed.store(exact_request, Ordering::SeqCst);
                    if exact_request {
                        (StatusCode::OK, "<VersioningConfiguration/>")
                    } else {
                        (StatusCode::BAD_REQUEST, "")
                    }
                }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let result = store(&format!("http://{address}"), "registry")
            .ensure_unversioned()
            .await;
        server.abort();
        result.unwrap();
        assert!(received.load(Ordering::SeqCst));
    }

    #[test]
    fn strict_storage_configuration_and_debug_are_value_free() {
        for endpoint in [
            "http://storage.example",
            "https://user:canary@storage.example",
            "https://storage.example/path",
            "https://storage.example?canary",
            "https://storage.example#canary",
            "file:///canary",
        ] {
            assert_eq!(
                AttachmentStorageConfig::from_raw(serde_json::from_value(raw(endpoint)).unwrap())
                    .unwrap_err(),
                AttachmentStorageError::InvalidConfiguration
            );
        }
        for (key, value) in [
            ("bucket", json!("../canary")),
            ("bucket", json!("127.0.0.1")),
            ("region", json!("us/east")),
            ("timeoutMilliseconds", json!(0)),
            ("accessKeyIdRef", json!("inline-secret-canary")),
        ] {
            let mut input = raw("https://storage.example");
            input[key] = value;
            assert!(
                AttachmentStorageConfig::from_raw(serde_json::from_value(input).unwrap()).is_err()
            );
        }
        assert!(serde_json::from_value::<RawAttachmentStorageConfig>(
            json!({"kind":"database", "endpoint":"https://ignored.example"})
        )
        .is_err());
        let mut input = raw("https://storage.example");
        input["secretAccessKey"] = json!("inline-canary");
        assert!(serde_json::from_value::<RawAttachmentStorageConfig>(input).is_err());
        let config = AttachmentStorageConfig::from_raw(
            serde_json::from_value(raw("https://storage.example")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            format!("{config:?}"),
            "AttachmentStorageConfig::S3(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", store("http://127.0.0.1:1234", "registry")),
            "S3AttachmentStore(<redacted>)"
        );
        let mut input = raw("http://127.0.0.1:1234");
        input["pathStyle"] = json!(false);
        assert!(AttachmentStorageConfig::from_raw(serde_json::from_value(input).unwrap()).is_err());
    }

    #[test]
    #[cfg(feature = "schema")]
    fn storage_schema_refuses_inline_credentials_and_database_extras() {
        let schema = crate::runtime_config::runtime_config_schema().unwrap();
        let storage_schema = schema.pointer("/$defs/RawAttachmentStorageConfig").unwrap();
        let validator = jsonschema::JSONSchema::compile(storage_schema).unwrap();
        let mut input = raw("https://storage.example");
        assert!(validator.is_valid(&input));
        input["accessKeyIdRef"] = json!("inline-credential-canary");
        assert!(!validator.is_valid(&input));
        assert!(
            !validator.is_valid(&json!({"kind":"database", "endpoint":"https://ignored.example"}))
        );
    }

    #[tokio::test]
    async fn database_default_needs_no_storage_service() {
        let files = SecretFiles::new();
        let config = AttachmentStorageConfig::from_raw(
            serde_json::from_value(json!({"kind":"database"})).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            config
                .activate("registry", &files.resolver())
                .await
                .unwrap(),
            AttachmentStorage::Database
        ));
    }

    #[test]
    fn bucket_versioning_parser_fails_closed() {
        for value in ["<VersioningConfiguration/>", "<?xml version=\"1.0\"?><VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></VersioningConfiguration>"] {
            validate_unversioned_xml(value.as_bytes()).unwrap();
        }
        for state in ["Enabled", "Suspended", "", "unknown"] {
            let document = format!(
                "<VersioningConfiguration><Status>{state}</Status></VersioningConfiguration>"
            );
            assert_eq!(
                validate_unversioned_xml(document.as_bytes()),
                Err(AttachmentStorageError::VersionedBucket)
            );
        }
        for value in [
            "",
            "<Other/>",
            "<VersioningConfiguration>",
            "<VersioningConfiguration/><VersioningConfiguration/>",
            "<!DOCTYPE canary><VersioningConfiguration/>",
            "<VersioningConfiguration>canary</VersioningConfiguration>",
        ] {
            assert!(validate_unversioned_xml(value.as_bytes()).is_err());
        }
    }

    #[test]
    fn object_keys_are_registry_scoped_and_digest_only() {
        let one = store("http://127.0.0.1:1234", "registry-one");
        let two = store("http://127.0.0.1:1234", "registry-two");
        let digest = hex::encode(Sha256::digest(b"content"));
        assert_ne!(
            one.object_url(&digest).unwrap(),
            two.object_url(&digest).unwrap()
        );
        for bad in ["../secret", "", "https://storage.example", &"A".repeat(64)] {
            assert!(one.object_url(bad).is_err());
        }
        assert!(verify_content(&digest, 7, b"corrupt").is_err());
        assert!(verify_content(&digest, 6, b"content").is_err());
    }

    async fn mock(body: &'static str, status: StatusCode) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{routing::any, Router};
        let app = Router::new().fallback(any(move || async move { (status, body) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (endpoint, handle)
    }

    #[tokio::test]
    async fn storage_binding_identity_tracks_namespace_but_allows_timeout_changes() {
        let (endpoint, server) = mock("<VersioningConfiguration/>", StatusCode::OK).await;
        let files = SecretFiles::new();
        let config =
            AttachmentStorageConfig::from_raw(serde_json::from_value(raw(&endpoint)).unwrap())
                .unwrap();
        let first = config
            .activate("database-one/registry", &files.resolver())
            .await
            .unwrap();
        let second = config
            .activate("database-two/registry", &files.resolver())
            .await
            .unwrap();
        assert_ne!(first.binding_digest(), second.binding_digest());
        let mut input = raw(&endpoint);
        input["timeoutMilliseconds"] = json!(5000);
        let tuning =
            AttachmentStorageConfig::from_raw(serde_json::from_value(input.clone()).unwrap())
                .unwrap();
        assert_eq!(
            first.binding_digest(),
            tuning
                .activate("database-one/registry", &files.resolver())
                .await
                .unwrap()
                .binding_digest()
        );
        input["bucket"] = json!("different-bucket");
        let moved =
            AttachmentStorageConfig::from_raw(serde_json::from_value(input).unwrap()).unwrap();
        assert_ne!(
            first.binding_digest(),
            moved
                .activate("database-one/registry", &files.resolver())
                .await
                .unwrap()
                .binding_digest()
        );
        server.abort();
    }

    #[tokio::test]
    async fn downloads_refuse_missing_corrupt_oversized_and_redirect_responses() {
        let digest = hex::encode(Sha256::digest(b"content"));
        for (body, status, error) in [
            (
                "content",
                StatusCode::NOT_FOUND,
                AttachmentStorageError::Missing,
            ),
            (
                "content",
                StatusCode::FOUND,
                AttachmentStorageError::Unavailable,
            ),
            ("corrupt", StatusCode::OK, AttachmentStorageError::Integrity),
            (
                "content-too-long",
                StatusCode::OK,
                AttachmentStorageError::Integrity,
            ),
        ] {
            let (endpoint, server) = mock(body, status).await;
            assert_eq!(
                store(&endpoint, "registry").get(&digest, 7).await,
                Err(error)
            );
            server.abort();
        }
        let (endpoint, server) = mock("content", StatusCode::OK).await;
        assert_eq!(
            store(&endpoint, "registry").get(&digest, 7).await.unwrap(),
            b"content"
        );
        server.abort();
    }

    #[tokio::test]
    async fn writes_verify_remote_bytes_and_deletion_can_be_retried() {
        use axum::{extract::Request, routing::any, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let deletes = Arc::new(AtomicUsize::new(0));
        let count = deletes.clone();
        let app = Router::new().fallback(any(move |request: Request| {
            let count = count.clone();
            async move {
                if request.uri().query() == Some("versioning=") {
                    (StatusCode::OK, "<VersioningConfiguration/>")
                } else if request.method() == Method::DELETE {
                    if count.fetch_add(1, Ordering::SeqCst) == 0 {
                        (StatusCode::SERVICE_UNAVAILABLE, "backend-secret-canary")
                    } else {
                        (StatusCode::NO_CONTENT, "")
                    }
                } else if request.method() == Method::PUT {
                    (StatusCode::OK, "")
                } else if count.load(Ordering::SeqCst) > 0 {
                    (StatusCode::NOT_FOUND, "")
                } else {
                    (StatusCode::OK, "corrupt")
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let store = store(&endpoint, "registry");
        let digest = hex::encode(Sha256::digest(b"content"));
        assert_eq!(
            store.put(&digest, b"content".to_vec()).await,
            Err(AttachmentStorageError::Integrity)
        );
        let error = store.delete(&digest).await.unwrap_err();
        assert_eq!(error, AttachmentStorageError::Unavailable);
        assert!(!format!("{error:?} {error}").contains("canary"));
        store.delete(&digest).await.unwrap();
        assert_eq!(deletes.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn download_refuses_interrupted_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npart")
                .await
                .unwrap();
        });
        let digest = hex::encode(Sha256::digest(b"content"));
        assert_eq!(
            store(&endpoint, "registry").get(&digest, 7).await,
            Err(AttachmentStorageError::Integrity)
        );
        server.await.unwrap();
    }

    /// Run against a disposable MinIO service with the synthetic credentials
    /// above. This test creates a private bucket and enables then suspends versioning.
    #[tokio::test]
    #[ignore = "requires BREG_TEST_S3_ENDPOINT pointing to disposable MinIO"]
    async fn real_s3_put_get_deduplicate_delete_and_version_refusal() {
        let endpoint =
            std::env::var("BREG_TEST_S3_ENDPOINT").expect("disposable S3 endpoint required");
        let mut store = store(&endpoint, &uuid::Uuid::new_v4().to_string());
        let bucket = format!("breg-{}", uuid::Uuid::new_v4());
        store.bucket_url.set_path(&format!("/{bucket}"));
        require_success(
            &store
                .send(Method::PUT, store.bucket_url.clone(), Vec::new())
                .await
                .unwrap(),
        )
        .unwrap();
        store.ensure_unversioned().await.unwrap();
        let bytes = b"synthetic request attachment".to_vec();
        let digest = hex::encode(Sha256::digest(&bytes));
        store.put(&digest, bytes.clone()).await.unwrap();
        store.put(&digest, bytes.clone()).await.unwrap();
        assert_eq!(store.get(&digest, bytes.len() as u64).await.unwrap(), bytes);
        assert_eq!(
            store.get(&digest, 1).await,
            Err(AttachmentStorageError::Integrity)
        );
        require_success(
            &store
                .send(
                    Method::PUT,
                    store.object_url(&digest).unwrap(),
                    b"corrupt content".to_vec(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.get(&digest, bytes.len() as u64).await,
            Err(AttachmentStorageError::Integrity)
        );
        store.put(&digest, bytes.clone()).await.unwrap();
        let response = store
            .send(Method::GET, store.bucket_url.clone(), Vec::new())
            .await
            .unwrap();
        let listing =
            String::from_utf8(read_bounded(response, MAXIMUM_CONTROL_BYTES).await.unwrap())
                .unwrap();
        assert_eq!(
            listing.matches("<Contents>").count(),
            1,
            "identical content has one physical object"
        );
        // A rejected authenticated attempt must leave the retained object intact;
        // retrying with the valid deployment credential can finish deletion.
        let files = SecretFiles::new();
        std::fs::write(files.0.join("secret"), "wrong-test-secret").unwrap();
        let mut rejected = self::store(&endpoint, "retry");
        rejected.bucket_url = store.bucket_url.clone();
        rejected.scope = store.scope.clone();
        rejected.secret_access_key = files.resolver().resolve("secret:file/secret").unwrap();
        assert_eq!(
            rejected.delete(&digest).await,
            Err(AttachmentStorageError::Unavailable)
        );
        assert_eq!(store.get(&digest, bytes.len() as u64).await.unwrap(), bytes);
        store.delete(&digest).await.unwrap();
        store.delete(&digest).await.unwrap();
        assert_eq!(
            store.get(&digest, bytes.len() as u64).await,
            Err(AttachmentStorageError::Missing)
        );
        // Simulate a PUT whose backend completion arrived after the first
        // deletion confirmation. A durable SQL tombstone can reconcile it again.
        require_success(
            &store
                .send(
                    Method::PUT,
                    store.object_url(&digest).unwrap(),
                    bytes.clone(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(store.get(&digest, bytes.len() as u64).await.unwrap(), bytes);
        store.delete(&digest).await.unwrap();
        assert_eq!(
            store.get(&digest, bytes.len() as u64).await,
            Err(AttachmentStorageError::Missing)
        );
        let mut versioning_url = store.bucket_url.clone();
        versioning_url.set_query(Some("versioning="));
        let enabled = br#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
        require_success(
            &store
                .send(Method::PUT, versioning_url.clone(), enabled)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.ensure_unversioned().await,
            Err(AttachmentStorageError::VersionedBucket)
        );
        assert_eq!(
            store.put(&digest, bytes.clone()).await,
            Err(AttachmentStorageError::VersionedBucket)
        );
        assert_eq!(
            store.delete(&digest).await,
            Err(AttachmentStorageError::VersionedBucket)
        );
        let suspended = br#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Suspended</Status></VersioningConfiguration>"#.to_vec();
        require_success(
            &store
                .send(Method::PUT, versioning_url, suspended)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.ensure_unversioned().await,
            Err(AttachmentStorageError::VersionedBucket)
        );
        require_success(
            &store
                .send(Method::DELETE, store.bucket_url.clone(), Vec::new())
                .await
                .unwrap(),
        )
        .unwrap();
    }
}
