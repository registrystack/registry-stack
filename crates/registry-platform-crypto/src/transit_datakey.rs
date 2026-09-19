// SPDX-License-Identifier: Apache-2.0

//! Data-encryption-key (DEK) custody through the Vault/OpenBao Transit API.
//!
//! The Transit datakey endpoints never export key material permanently: a
//! generated DEK is returned once in plaintext alongside a wrapped form, and
//! only the wrapped form is stored. [`TransitDataKeyClient`] generates,
//! unwraps, and self-tests that exchange over the same trusted local Unix
//! socket proxy the Transit signer uses. Configuration details are redacted
//! from `Debug` because socket, mount, and key names reveal deployment
//! topology.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{
    build_transit_client, parse_json_strict, read_bounded_transit_response, transit_error,
    valid_transit_path, valid_transit_segment, SigningError, MAX_TRANSIT_REQUEST_TIMEOUT,
};

/// Datakey bit width. The field-envelope DEK is always an AES-256 key.
pub const TRANSIT_DATAKEY_BITS: u16 = 256;
/// Bound on an accepted wrapped-datakey ciphertext, well above the wrapped
/// form of one 256-bit key.
const MAX_WRAPPED_DATAKEY_CHARS: usize = 1024;
/// The datakey type Transit must report for custody to be acceptable.
const TRANSIT_DATAKEY_TYPE: &str = "aes256-gcm";

/// Validated connection and key binding for a Transit data-encryption key.
///
/// The same validation posture as [`crate::TransitSignerConfig`]: absolute
/// Unix socket, well-formed mount path and key name, and a bounded nonzero
/// request timeout.
#[derive(Clone)]
pub struct TransitDataKeyConfig {
    socket_path: PathBuf,
    mount_path: String,
    key_name: String,
    request_timeout: Duration,
}

impl TransitDataKeyConfig {
    /// Bind one Transit key as the custodian of BReg field-encryption data
    /// keys.
    ///
    /// # Errors
    /// [`SigningError`] when the socket path is not absolute, the mount path
    /// or key name is not a well-formed Transit path segment, or the timeout
    /// is zero or above the provider maximum.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        mount_path: impl Into<String>,
        key_name: impl Into<String>,
        request_timeout: Duration,
    ) -> Result<Self, SigningError> {
        let socket_path = socket_path.into();
        let mount_path = mount_path.into();
        let key_name = key_name.into();
        if !socket_path.is_absolute()
            || !valid_transit_path(&mount_path)
            || !valid_transit_segment(&key_name)
            || request_timeout.is_zero()
            || request_timeout > MAX_TRANSIT_REQUEST_TIMEOUT
        {
            return Err(transit_error("transit datakey configuration is invalid"));
        }
        Ok(Self {
            socket_path,
            mount_path,
            key_name,
            request_timeout,
        })
    }

    /// The absolute Unix-socket path requests are sent through.
    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// The Transit mount path, for URL construction only.
    #[must_use]
    pub fn mount_path(&self) -> &str {
        &self.mount_path
    }

    /// The Transit key name, for URL construction only.
    #[must_use]
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// The per-request timeout.
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }
}

impl fmt::Debug for TransitDataKeyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitDataKeyConfig")
            .field("bits", &TRANSIT_DATAKEY_BITS)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

/// Generates and unwraps field-encryption data keys held by Transit.
///
/// Construction validates key custody metadata and proves both endpoints with
/// a generate-and-unwrap self-test whose plaintexts must match. Every
/// plaintext the client returns is zeroized on drop.
pub struct TransitDataKeyClient {
    client: reqwest::Client,
    metadata_url: String,
    datakey_url: String,
    decrypt_url: String,
    request_timeout: Duration,
}

impl TransitDataKeyClient {
    /// Connect to Transit, validate datakey custody metadata, and prove
    /// generate-and-unwrap access.
    ///
    /// # Errors
    /// [`SigningError`] when the provider is unreachable, reports unsafe key
    /// custody, or fails the generate-and-unwrap self-test.
    pub async fn initialize(config: TransitDataKeyConfig) -> Result<Self, SigningError> {
        let client = Self {
            client: build_transit_client(config.socket_path())?,
            metadata_url: format!(
                "http://localhost/v1/{}/keys/{}",
                config.mount_path(),
                config.key_name()
            ),
            datakey_url: format!(
                "http://localhost/v1/{}/datakey/plaintext/{}",
                config.mount_path(),
                config.key_name()
            ),
            decrypt_url: format!(
                "http://localhost/v1/{}/decrypt/{}",
                config.mount_path(),
                config.key_name()
            ),
            request_timeout: config.request_timeout(),
        };
        let metadata = client
            .request_json(reqwest::Method::GET, &client.metadata_url, None)
            .await
            .map_err(|_| transit_error("transit datakey metadata is unavailable"))?;
        client
            .validate_metadata(&metadata)
            .map_err(|_| transit_error("transit datakey metadata is invalid"))?;
        client
            .self_test()
            .await
            .map_err(|_| transit_error("transit datakey self-test failed"))?;
        Ok(client)
    }

    /// Generate one 256-bit data key, returning its plaintext and the wrapped
    /// form to persist.
    ///
    /// # Errors
    /// [`SigningError`] when the provider refuses the request or answers with
    /// anything but a well-formed plaintext/wrapped pair.
    pub async fn generate_datakey(&self) -> Result<(Zeroizing<[u8; 32]>, String), SigningError> {
        let document = self
            .request_json(
                reqwest::Method::POST,
                &self.datakey_url,
                Some(&json!({ "bits": TRANSIT_DATAKEY_BITS })),
            )
            .await?;
        let data = document
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(|| transit_error("transit datakey response is invalid"))?;
        let plaintext = data
            .get("plaintext")
            .and_then(Value::as_str)
            .ok_or_else(|| transit_error("transit datakey response is invalid"))?;
        let wrapped = data
            .get("ciphertext")
            .and_then(Value::as_str)
            .ok_or_else(|| transit_error("transit datakey response is invalid"))?;
        let plaintext = decode_datakey_plaintext(plaintext)?;
        validate_wrapped_datakey(wrapped)?;
        Ok((plaintext, wrapped.to_owned()))
    }

    /// Unwrap one stored wrapped data key back to its plaintext.
    ///
    /// # Errors
    /// [`SigningError`] when the wrapped form is malformed, the provider
    /// refuses the request, or the returned plaintext is not a 256-bit key.
    pub async fn unwrap_datakey(&self, wrapped: &str) -> Result<Zeroizing<[u8; 32]>, SigningError> {
        validate_wrapped_datakey(wrapped)?;
        let document = self
            .request_json(
                reqwest::Method::POST,
                &self.decrypt_url,
                Some(&json!({ "ciphertext": wrapped })),
            )
            .await?;
        let plaintext = document
            .get("data")
            .and_then(|data| data.get("plaintext"))
            .and_then(Value::as_str)
            .ok_or_else(|| transit_error("transit datakey response is invalid"))?;
        decode_datakey_plaintext(plaintext)
    }

    /// Generate and unwrap one data key, refusing any provider whose two
    /// plaintexts disagree.
    async fn self_test(&self) -> Result<(), SigningError> {
        let (generated, wrapped) = self.generate_datakey().await?;
        let unwrapped = self.unwrap_datakey(&wrapped).await?;
        if generated.as_ref() != unwrapped.as_ref() {
            return Err(transit_error("transit datakey self-test failed"));
        }
        Ok(())
    }

    async fn request_json(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&Value>,
    ) -> Result<Value, SigningError> {
        let mut request = self
            .client
            .request(method, url)
            .header("X-Vault-Request", "true")
            .timeout(self.request_timeout);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| transit_error("transit datakey provider request failed"))?;
        if !response.status().is_success() {
            return Err(transit_error("transit datakey provider request failed"));
        }
        let bytes = read_bounded_transit_response(response).await?;
        parse_json_strict(&bytes).map_err(|_| transit_error("transit datakey response is invalid"))
    }

    /// The datakey key must be a non-exportable, non-derived AES-256-GCM key
    /// that supports encryption and cannot be backed up in plaintext.
    fn validate_metadata(&self, document: &Value) -> Result<(), SigningError> {
        let data = document
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(|| transit_error("transit datakey metadata is invalid"))?;
        let required_false = ["exportable", "derived", "allow_plaintext_backup"];
        if data.get("type").and_then(Value::as_str) != Some(TRANSIT_DATAKEY_TYPE)
            || data.get("supports_encryption").and_then(Value::as_bool) != Some(true)
            || required_false
                .iter()
                .any(|field| data.get(*field).and_then(Value::as_bool) != Some(false))
        {
            return Err(transit_error("transit datakey custody is invalid"));
        }
        Ok(())
    }
}

impl fmt::Debug for TransitDataKeyClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitDataKeyClient")
            .field("bits", &TRANSIT_DATAKEY_BITS)
            .finish_non_exhaustive()
    }
}

/// Read the Transit key version out of a `vault:v{N}:` wrapped-datakey
/// prefix.
///
/// # Errors
/// [`SigningError`] when the wrapped form does not carry a well-formed
/// nonzero version prefix.
pub fn transit_wrapped_key_version(wrapped: &str) -> Result<u32, SigningError> {
    validate_wrapped_datakey(wrapped)?;
    let version = wrapped
        .strip_prefix("vault:v")
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(version, _)| version.parse::<u32>().ok())
        .expect("validate_wrapped_datakey proved the version parses");
    Ok(version)
}

/// A wrapped datakey must be a `vault:v{N}:`-prefixed, size-bounded string
/// whose version is a nonzero u32 and whose payload is standard base64.
fn validate_wrapped_datakey(wrapped: &str) -> Result<(), SigningError> {
    let invalid = || transit_error("transit datakey ciphertext is invalid");
    if wrapped.len() > MAX_WRAPPED_DATAKEY_CHARS {
        return Err(invalid());
    }
    let Some((version, payload)) = wrapped
        .strip_prefix("vault:v")
        .and_then(|rest| rest.split_once(':'))
    else {
        return Err(invalid());
    };
    let version_valid = !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && version.parse::<u32>().is_ok_and(|parsed| parsed > 0);
    let payload_valid = !payload.is_empty()
        && payload
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='));
    if !version_valid || !payload_valid {
        return Err(invalid());
    }
    Ok(())
}

/// Decode one base64 datakey plaintext, refusing any length but 32 bytes.
fn decode_datakey_plaintext(plaintext: &str) -> Result<Zeroizing<[u8; 32]>, SigningError> {
    if plaintext.len() > MAX_WRAPPED_DATAKEY_CHARS {
        return Err(transit_error("transit datakey plaintext is invalid"));
    }
    let decoded = STANDARD
        .decode(plaintext)
        .map_err(|_| transit_error("transit datakey plaintext is invalid"))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| transit_error("transit datakey plaintext is invalid"))?;
    Ok(Zeroizing::new(bytes))
}

#[cfg(all(test, unix, feature = "transit"))]
mod tests {
    use super::*;
    use crate::transit_mock::{spawn_transit_mock, transit_reply, MockTransitReply};
    use tempfile::TempDir;
    use tokio::task::JoinHandle;

    const TIMEOUT: Duration = Duration::from_secs(5);
    const SOCKET: &str = "/run/transit/proxy.sock";
    const MOUNT: &str = "transit";
    const KEY: &str = "breg-field-dek";
    const METADATA_PATH: &str = "/v1/transit/keys/breg-field-dek";
    const DATAKEY_PATH: &str = "/v1/transit/datakey/plaintext/breg-field-dek";
    const DECRYPT_PATH: &str = "/v1/transit/decrypt/breg-field-dek";
    const DEK: [u8; 32] = [0x42; 32];
    const WRAPPED: &str = "vault:v3:QpQ=";

    /// A scripted provider kept alive for the duration of one test. The
    /// socket directory and server task live exactly as long as the guard.
    struct MockTransit {
        config: TransitDataKeyConfig,
        _directory: TempDir,
        _server: JoinHandle<()>,
    }

    fn spawn(replies: Vec<MockTransitReply>) -> MockTransit {
        let (directory, socket_path, server) = spawn_transit_mock(replies);
        let config = TransitDataKeyConfig::new(socket_path, MOUNT, KEY, TIMEOUT)
            .expect("mock socket config validates");
        MockTransit {
            config,
            _directory: directory,
            _server: server,
        }
    }

    fn config() -> TransitDataKeyConfig {
        TransitDataKeyConfig::new(SOCKET, MOUNT, KEY, TIMEOUT).expect("fixture config validates")
    }

    fn datakey_metadata(overrides: Value) -> Value {
        let mut data = json!({
            "type": "aes256-gcm",
            "supports_encryption": true,
            "exportable": false,
            "derived": false,
            "allow_plaintext_backup": false,
            "latest_version": 3,
            "min_decryption_version": 1,
            "min_encryption_version": 1,
        });
        let object = data.as_object_mut().expect("metadata object");
        if let Value::Object(overrides) = overrides {
            for (member, value) in overrides {
                object.insert(member, value);
            }
        }
        json!({ "data": data })
    }

    fn datakey_response() -> Value {
        json!({
            "data": {
                "plaintext": STANDARD.encode(DEK),
                "ciphertext": WRAPPED,
            }
        })
    }

    fn decrypt_response() -> Value {
        json!({ "data": { "plaintext": STANDARD.encode(DEK) } })
    }

    fn metadata_reply() -> MockTransitReply {
        transit_reply("GET", METADATA_PATH, None, datakey_metadata(json!({})))
    }

    fn datakey_reply() -> MockTransitReply {
        transit_reply(
            "POST",
            DATAKEY_PATH,
            Some(json!({ "bits": 256 })),
            datakey_response(),
        )
    }

    fn decrypt_reply(response: Value) -> MockTransitReply {
        transit_reply(
            "POST",
            DECRYPT_PATH,
            Some(json!({ "ciphertext": WRAPPED })),
            response,
        )
    }

    fn client_for(transit: &MockTransit, decrypt_url: String) -> TransitDataKeyClient {
        TransitDataKeyClient {
            client: build_transit_client(transit.config.socket_path()).expect("mock client builds"),
            metadata_url: String::new(),
            datakey_url: String::new(),
            decrypt_url,
            request_timeout: TIMEOUT,
        }
    }

    #[tokio::test]
    async fn initialize_validates_custody_and_round_trips_a_datakey() {
        let transit = spawn(vec![
            metadata_reply(),
            datakey_reply(),
            decrypt_reply(decrypt_response()),
            datakey_reply(),
            decrypt_reply(decrypt_response()),
        ]);
        let client = TransitDataKeyClient::initialize(transit.config.clone())
            .await
            .expect("mock Transit accepts the datakey client");
        let (generated, wrapped) = client.generate_datakey().await.expect("datakey generates");
        assert_eq!(generated.as_ref(), &DEK);
        assert_eq!(wrapped, WRAPPED);
        let unwrapped = client
            .unwrap_datakey(&wrapped)
            .await
            .expect("datakey unwraps");
        assert_eq!(unwrapped.as_ref(), &DEK);
    }

    #[tokio::test]
    async fn initialize_refuses_every_unsafe_custody_answer() {
        let unsafe_metadata = [
            (
                "wrong_type",
                datakey_metadata(json!({ "type": "aes128-gcm" })),
            ),
            (
                "encryption_unsupported",
                datakey_metadata(json!({ "supports_encryption": false })),
            ),
            (
                "exportable",
                datakey_metadata(json!({ "exportable": true })),
            ),
            ("derived", datakey_metadata(json!({ "derived": true }))),
            (
                "plaintext_backup",
                datakey_metadata(json!({ "allow_plaintext_backup": true })),
            ),
        ];
        for (case, metadata) in unsafe_metadata {
            let transit = spawn(vec![transit_reply("GET", METADATA_PATH, None, metadata)]);
            let result = TransitDataKeyClient::initialize(transit.config.clone()).await;
            assert!(result.is_err(), "{case} custody must be refused");
        }
        let shapeless = spawn(vec![transit_reply(
            "GET",
            METADATA_PATH,
            None,
            json!({ "not_data": true }),
        )]);
        assert!(TransitDataKeyClient::initialize(shapeless.config.clone())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn initialize_refuses_a_self_test_whose_plaintexts_disagree() {
        let mismatched = json!({ "data": { "plaintext": STANDARD.encode([0x43; 32]) } });
        let transit = spawn(vec![
            metadata_reply(),
            datakey_reply(),
            decrypt_reply(mismatched),
        ]);
        assert!(TransitDataKeyClient::initialize(transit.config.clone())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn unwrap_refuses_wrong_length_plaintext() {
        for plaintext in [
            STANDARD.encode([0x42; 31]),
            STANDARD.encode([0x42; 33]),
            "not base64!".to_owned(),
        ] {
            let transit = spawn(vec![decrypt_reply(
                json!({ "data": { "plaintext": plaintext } }),
            )]);
            let client = client_for(&transit, format!("http://localhost{DECRYPT_PATH}"));
            assert!(
                client.unwrap_datakey(WRAPPED).await.is_err(),
                "a malformed plaintext must never become a data key"
            );
        }
    }

    #[tokio::test]
    async fn provider_failures_map_to_value_free_errors() {
        let transit = spawn(vec![MockTransitReply {
            method: "POST",
            path: DECRYPT_PATH,
            body: Some(json!({ "ciphertext": WRAPPED })),
            status: 500,
            response: b"{\"error\":\"decryption failed for the named key\"}".to_vec(),
            delay: Duration::ZERO,
        }]);
        let client = client_for(&transit, format!("http://localhost{DECRYPT_PATH}"));
        let error = client
            .unwrap_datakey(WRAPPED)
            .await
            .expect_err("provider failure surfaces");
        let rendered = error.to_string();
        assert!(!rendered.contains(KEY), "no key name in {rendered}");
        assert!(
            !rendered.contains("decryption failed"),
            "no provider detail in {rendered}"
        );
    }

    #[test]
    fn config_validates_the_same_bounds_as_the_signer() {
        assert!(TransitDataKeyConfig::new(SOCKET, MOUNT, KEY, TIMEOUT).is_ok());
        assert!(TransitDataKeyConfig::new("relative.sock", MOUNT, KEY, TIMEOUT).is_err());
        assert!(TransitDataKeyConfig::new(SOCKET, "", KEY, TIMEOUT).is_err());
        assert!(TransitDataKeyConfig::new(SOCKET, "a/../b", KEY, TIMEOUT).is_err());
        assert!(TransitDataKeyConfig::new(SOCKET, MOUNT, "..", TIMEOUT).is_err());
        assert!(TransitDataKeyConfig::new(SOCKET, MOUNT, KEY, Duration::ZERO).is_err());
        assert!(TransitDataKeyConfig::new(SOCKET, MOUNT, KEY, Duration::from_secs(31)).is_err());
        let config = config();
        assert_eq!(config.mount_path(), MOUNT);
        assert_eq!(config.key_name(), KEY);
        assert_eq!(config.request_timeout(), TIMEOUT);
        assert_eq!(config.socket_path(), std::path::Path::new(SOCKET));
    }

    #[test]
    fn debug_output_carries_no_connection_details() {
        let client = TransitDataKeyClient {
            client: reqwest::Client::new(),
            metadata_url: String::new(),
            datakey_url: String::new(),
            decrypt_url: String::new(),
            request_timeout: TIMEOUT,
        };
        for rendered in [format!("{:?}", config()), format!("{:?}", client)] {
            assert!(!rendered.contains(SOCKET), "no socket path in {rendered}");
            assert!(!rendered.contains(MOUNT), "no mount path in {rendered}");
            assert!(!rendered.contains(KEY), "no key name in {rendered}");
        }
    }

    #[test]
    fn wrapped_key_version_parses_only_wellformed_prefixes() {
        assert_eq!(transit_wrapped_key_version("vault:v3:QpQ=").unwrap(), 3);
        assert_eq!(transit_wrapped_key_version("vault:v12:AA==").unwrap(), 12);
        for wrapped in [
            "",
            "vault:",
            "vault:v:QpQ=",
            "vault:v0:QpQ=",
            "vault:vX:QpQ=",
            "vault:v3:",
            "vault:v3:not base64!",
            "kms:v3:QpQ=",
            "vault:v4294967296:QpQ=",
            &"x".repeat(MAX_WRAPPED_DATAKEY_CHARS + 1),
        ] {
            assert!(
                transit_wrapped_key_version(wrapped).is_err(),
                "{wrapped} is not a wrapped datakey"
            );
        }
    }
}
