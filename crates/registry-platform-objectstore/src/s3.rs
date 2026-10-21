// SPDX-License-Identifier: Apache-2.0
//! Deployment-bound S3-compatible content storage. The calling product owns
//! references, locking, pending writes and durable deletion retries; this
//! transport owns only bytes.

use std::{fmt, net::IpAddr, time::Duration};

use hmac::{Hmac, KeyInit, Mac};
use quick_xml::{events::Event, Reader};
use registry_platform_config::{
    ObjectStorageConfig, ProtectedSecret, SecretReference, SecretResolver,
};
use registry_platform_httputil::{read_bounded, validate_response_headers, OutboundClientBuilder};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Method, StatusCode, Url,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const MAXIMUM_CONTROL_BYTES: u64 = 16 * 1024;
const MAXIMUM_URL_BYTES: usize = 2048;
const MAXIMUM_SCOPE_INPUT_BYTES: usize = 1024;
const MAXIMUM_SECRET_BYTES: usize = 4096;
const MAXIMUM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Storage failures carry no URLs, object keys, credentials or backend responses.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ObjectStoreError {
    #[error("object storage configuration is invalid")]
    InvalidConfiguration,
    #[error("object storage secret resolution failed")]
    Secret,
    #[error("object storage is unavailable")]
    Unavailable,
    #[error("stored content is unavailable")]
    Missing,
    #[error("stored content failed integrity validation")]
    Integrity,
    #[error("object storage requires a bucket that has never enabled versioning")]
    VersionedBucket,
}

type Result<T> = std::result::Result<T, ObjectStoreError>;

/// What the calling product fixes about its objects. The key prefix places
/// every object under `{prefix}/` in the bucket, and the binding domain is
/// the first member of the identity the binding digest commits to, so two
/// products sharing a bucket never share a key or a binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectNamespace {
    /// One path segment: 1 to 64 lowercase letters, digits, or `-`.
    pub key_prefix: &'static str,
    /// 1 to 128 printable ASCII characters, for example `breg-attachment-s3-v1`.
    pub binding_domain: &'static str,
    /// The largest object written or read, in bytes.
    pub max_object_bytes: u64,
}

impl ObjectNamespace {
    fn check(&self) -> Result<()> {
        let prefix = self.key_prefix.as_bytes();
        if prefix.is_empty()
            || prefix.len() > 64
            || !prefix
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            || self.binding_domain.is_empty()
            || self.binding_domain.len() > 128
            || !self.binding_domain.bytes().all(|b| b.is_ascii_graphic())
            || self.max_object_bytes == 0
        {
            return Err(ObjectStoreError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Validated, unresolved storage settings. Debug never reveals deployment values.
#[derive(Clone)]
pub struct S3Settings {
    bucket_url: Url,
    region: String,
    access_key_id_ref: SecretReference,
    secret_access_key_ref: SecretReference,
    session_token_ref: Option<SecretReference>,
    ca_bundle_ref: Option<SecretReference>,
    timeout: Duration,
}

impl S3Settings {
    /// Refuse what the shared block's decode does not: a non-loopback
    /// `http` URL, a URL with a path, query or fragment, a malformed bucket
    /// or region name, and a virtual-hosted bucket on an IP address host.
    pub fn from_config(config: &ObjectStorageConfig) -> Result<Self> {
        let text = config.url.as_str();
        let mut url = Url::parse(text).map_err(|_| ObjectStoreError::InvalidConfiguration)?;
        let loopback = url
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        let bucket = config.bucket.as_str();
        let region = config.region.as_str();
        if text.len() > MAXIMUM_URL_BYTES
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
        {
            return Err(ObjectStoreError::InvalidConfiguration);
        }
        if config.path_style {
            url.set_path(&format!("/{bucket}"));
        } else {
            if url
                .host_str()
                .is_none_or(|host| host.parse::<IpAddr>().is_ok() || host.contains(':'))
            {
                return Err(ObjectStoreError::InvalidConfiguration);
            }
            url.set_host(Some(&format!(
                "{bucket}.{}",
                url.host_str().unwrap_or_default()
            )))
            .map_err(|_| ObjectStoreError::InvalidConfiguration)?;
        }
        Ok(Self {
            bucket_url: url,
            region: region.to_owned(),
            access_key_id_ref: config.access_key_id_ref.clone(),
            secret_access_key_ref: config.secret_access_key_ref.clone(),
            session_token_ref: config.session_token_ref.clone(),
            ca_bundle_ref: config.ca_bundle_ref.clone(),
            timeout: Duration::from_millis(config.attempt_timeout_milliseconds.get()),
        })
    }

    /// Resolve the credentials, bind the store to `namespace` and to the
    /// scope `scope_input` names, and refuse a bucket that has ever enabled
    /// versioning. The scope is hashed into every object key and the binding
    /// digest, so separate scopes never share an object or a deletion.
    pub async fn activate(
        &self,
        namespace: ObjectNamespace,
        scope_input: &str,
        resolver: &SecretResolver,
    ) -> Result<S3ObjectStore> {
        namespace.check()?;
        if scope_input.is_empty() || scope_input.len() > MAXIMUM_SCOPE_INPUT_BYTES {
            return Err(ObjectStoreError::InvalidConfiguration);
        }
        let resolve = |reference: &SecretReference| {
            resolver
                .resolve_reference(reference)
                .map_err(|_| ObjectStoreError::Secret)
        };
        let access_key_id = resolve(&self.access_key_id_ref)?;
        let secret_access_key = resolve(&self.secret_access_key_ref)?;
        let session_token = self.session_token_ref.as_ref().map(resolve).transpose()?;
        for secret in [&access_key_id, &secret_access_key]
            .into_iter()
            .chain(session_token.iter())
        {
            if secret.is_empty()
                || secret.len() > MAXIMUM_SECRET_BYTES
                || !secret.expose_secret().iter().all(|b| b.is_ascii_graphic())
            {
                return Err(ObjectStoreError::Secret);
            }
        }
        if !access_key_id
            .expose_secret()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return Err(ObjectStoreError::Secret);
        }
        let mut builder = OutboundClientBuilder::new()
            .timeout(self.timeout)
            .connect_timeout(connect_timeout(self.timeout));
        if let Some(reference) = &self.ca_bundle_ref {
            builder =
                builder.trusted_root_certificates(resolve(reference)?.expose_secret().to_vec());
        }
        let scope = hex::encode(Sha256::digest(scope_input.as_bytes()));
        let binding_digest = binding_digest(namespace, &self.bucket_url, &self.region, &scope)?;
        let store = S3ObjectStore {
            client: builder
                .try_build()
                .map_err(|_| ObjectStoreError::InvalidConfiguration)?,
            namespace,
            bucket_url: self.bucket_url.clone(),
            region: self.region.clone(),
            scope,
            access_key_id,
            secret_access_key,
            session_token,
            binding_digest,
        };
        store.ensure_unversioned().await?;
        Ok(store)
    }
}

impl fmt::Debug for S3Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("S3Settings(<redacted>)")
    }
}

/// The connect phase of one attempt never outlasts the attempt, and never
/// waits more than five seconds.
fn connect_timeout(timeout: Duration) -> Duration {
    timeout.min(MAXIMUM_CONNECT_TIMEOUT)
}

/// The hex SHA-256 of the JSON array `[domain, bucketUrl, region, scope]`:
/// it changes when the bucket, region or scope does, and survives a
/// credential rotation or timeout change.
fn binding_digest(
    namespace: ObjectNamespace,
    bucket_url: &Url,
    region: &str,
    scope: &str,
) -> Result<String> {
    let identity =
        serde_json::to_vec(&(namespace.binding_domain, bucket_url.as_str(), region, scope))
            .map_err(|_| ObjectStoreError::InvalidConfiguration)?;
    Ok(hex::encode(Sha256::digest(identity)))
}

/// Bounded SigV4 S3 operations, confined to one bucket and one hashed scope
/// under the caller's key prefix. Callers must hold their own content lock
/// through each mutating operation. No automatic retries occur: uncertain
/// writes and deletes are reconciled by the caller's durable pending-operation
/// records using the same deterministic key.
pub struct S3ObjectStore {
    client: reqwest::Client,
    namespace: ObjectNamespace,
    bucket_url: Url,
    region: String,
    scope: String,
    access_key_id: ProtectedSecret,
    secret_access_key: ProtectedSecret,
    session_token: Option<ProtectedSecret>,
    binding_digest: String,
}

impl fmt::Debug for S3ObjectStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("S3ObjectStore(<redacted>)")
    }
}

impl S3ObjectStore {
    /// Persist beside retained content; a changed binding cannot read or
    /// delete it.
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    fn object_url(&self, sha256: &str) -> Result<Url> {
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ObjectStoreError::Integrity);
        }
        let mut url = self.bucket_url.clone();
        let path = format!(
            "{}/{}/{}/{sha256}",
            url.path().trim_end_matches('/'),
            self.namespace.key_prefix,
            self.scope
        );
        url.set_path(&path);
        Ok(url)
    }

    /// Write the content under its digest, then read it back and check it.
    pub async fn put(&self, sha256: &str, bytes: Vec<u8>) -> Result<()> {
        let url = self.object_url(sha256)?;
        self.verify_content(sha256, bytes.len() as u64, &bytes)?;
        self.ensure_unversioned().await?;
        let size = bytes.len() as u64;
        let response = self.send(Method::PUT, url, bytes).await?;
        require_success(&response)?;
        require_unversioned_headers(response.headers())?;
        read_bounded(response, MAXIMUM_CONTROL_BYTES)
            .await
            .map_err(|_| ObjectStoreError::Unavailable)?;
        self.get(sha256, size).await?;
        Ok(())
    }

    /// Read exactly `expected_size` bytes whose SHA-256 is `sha256`.
    pub async fn get(&self, sha256: &str, expected_size: u64) -> Result<Vec<u8>> {
        if expected_size > self.namespace.max_object_bytes {
            return Err(ObjectStoreError::Integrity);
        }
        let response = self
            .send(Method::GET, self.object_url(sha256)?, Vec::new())
            .await?;
        require_success(&response)?;
        require_unversioned_headers(response.headers())?;
        let bytes = read_bounded(response, expected_size)
            .await
            .map_err(|_| ObjectStoreError::Integrity)?;
        self.verify_content(sha256, expected_size, &bytes)?;
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
            .map_err(|_| ObjectStoreError::Unavailable)?;
        self.ensure_unversioned().await?;
        let response = self.send(Method::GET, url, Vec::new()).await?;
        require_unversioned_headers(response.headers())?;
        if response.status() != StatusCode::NOT_FOUND {
            return Err(ObjectStoreError::Unavailable);
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
            .map_err(|_| ObjectStoreError::Unavailable)?;
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
            .map_err(|_| ObjectStoreError::Unavailable)?;
        validate_response_headers(response.headers()).map_err(|_| ObjectStoreError::Unavailable)?;
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
            .ok_or(ObjectStoreError::InvalidConfiguration)?;
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
                HeaderValue::from_str(value).map_err(|_| ObjectStoreError::InvalidConfiguration)?,
            );
        }
        if let Some(token) = &self.session_token {
            let mut value = HeaderValue::from_bytes(token.expose_secret())
                .map_err(|_| ObjectStoreError::Secret)?;
            value.set_sensitive(true);
            headers.insert("x-amz-security-token", value);
        }
        let (canonical, signed_names) = canonical_request(method, url, &headers, &payload_hash)?;
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
            .map_err(|_| ObjectStoreError::Secret)?;
        let authorization = Zeroizing::new(format!("AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={signed_names}, Signature={signature}"));
        let mut value =
            HeaderValue::from_str(&authorization).map_err(|_| ObjectStoreError::Secret)?;
        value.set_sensitive(true);
        headers.insert("authorization", value);
        Ok(headers)
    }

    fn verify_content(&self, sha256: &str, expected_size: u64, bytes: &[u8]) -> Result<()> {
        if expected_size > self.namespace.max_object_bytes
            || bytes.len() as u64 != expected_size
            || hex::encode(Sha256::digest(bytes)) != sha256
        {
            return Err(ObjectStoreError::Integrity);
        }
        Ok(())
    }
}

/// The SigV4 canonical request over every header in `headers`, and the
/// sorted `;`-joined names it signs. The query is signed as written, so a
/// caller passes only queries already in canonical order.
fn canonical_request(
    method: &Method,
    url: &Url,
    headers: &HeaderMap,
    payload_hash: &str,
) -> Result<(Zeroizing<String>, String)> {
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
                .map_err(|_| ObjectStoreError::Secret)?,
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
    Ok((canonical, signed_names))
}

fn hmac(key: &[u8], value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(value);
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

fn require_success(response: &reqwest::Response) -> Result<()> {
    if response.status() == StatusCode::NOT_FOUND {
        return Err(ObjectStoreError::Missing);
    }
    if !response.status().is_success() {
        return Err(ObjectStoreError::Unavailable);
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
        return Err(ObjectStoreError::VersionedBucket);
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
            .map_err(|_| ObjectStoreError::Unavailable)?
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
                return Err(ObjectStoreError::VersionedBucket)
            }
            _ => return Err(ObjectStoreError::Unavailable),
        }
    }
}

#[cfg(test)]
#[path = "s3_tests.rs"]
mod tests;
