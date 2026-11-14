// SPDX-License-Identifier: Apache-2.0

//! Raw RSA PKCS#1 v1.5 Transit signing and verification without a digest OID.
//!
//! The primitive sends a fixed-size lowercase hexadecimal digest to the
//! Unix-socket Transit provider. Product code owns headers, roles, custody
//! configuration, authorization, and outer signature encoding.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use aws_lc_rs::rsa::PublicKey as RsaPublicKey;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use pkcs1::der::Decode as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    build_transit_client_no_redirects, send_transit_json, transit_metadata_url,
    valid_transit_binding, TransitRequestFault,
};

const SELF_TEST_DIGEST: &[u8; 64] =
    b"0000000000000000000000000000000000000000000000000000000000000000";

/// Validated connection, provider identity, and immutable RSA key binding.
///
/// Socket, mount, and key names are deliberately absent from `Debug` and all
/// errors because they reveal deployment topology.
#[derive(Clone)]
pub struct TransitRsaNoOidKeyConfig {
    socket_path: PathBuf,
    mount_path: String,
    key_name: String,
    key_version: u32,
    public_key_sha256: [u8; 32],
    request_timeout: Duration,
}

impl TransitRsaNoOidKeyConfig {
    /// Bind the exact SPKI DER identity of one RSA Transit key version.
    ///
    /// # Errors
    ///
    /// Returns [`TransitRsaNoOidError::InvalidConfiguration`] when any local
    /// binding or request bound is unsafe.
    pub fn new(
        socket_path: PathBuf,
        mount_path: String,
        key_name: String,
        key_version: u32,
        public_key_sha256: [u8; 32],
        request_timeout: Duration,
    ) -> Result<Self, TransitRsaNoOidError> {
        if !valid_transit_binding(
            &socket_path,
            &mount_path,
            &key_name,
            key_version,
            request_timeout,
        ) {
            return Err(TransitRsaNoOidError::InvalidConfiguration);
        }
        Ok(Self {
            socket_path,
            mount_path,
            key_name,
            key_version,
            public_key_sha256,
            request_timeout,
        })
    }
}

impl fmt::Debug for TransitRsaNoOidKeyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitRsaNoOidKeyConfig")
            .finish_non_exhaustive()
    }
}

/// A raw RSA signature whose allocation is erased on drop.
pub struct TransitRsaNoOidSignature(Zeroizing<Vec<u8>>);

impl TransitRsaNoOidSignature {
    /// Borrow the exact RSA signature bytes, without an outer encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// A redacted refusal from the raw RSA Transit primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TransitRsaNoOidError {
    #[error("the Transit RSA configuration is invalid")]
    InvalidConfiguration,
    #[error("the Transit client could not be built for the configured Unix socket")]
    Client,
    #[error("the Transit provider did not answer on the configured Unix socket")]
    Unavailable,
    #[error("the Transit provider refused the request")]
    Refused,
    #[error("the Transit provider failed the request")]
    ProviderFailed,
    #[error("the Transit provider response is malformed or too large")]
    InvalidResponse,
    #[error("the Transit RSA key custody metadata is unsafe for this role")]
    UnsafeCustody,
    #[error("the configured Transit RSA key version has not been created")]
    KeyVersionNotCreated,
    #[error("the configured Transit RSA key version is retired for this operation")]
    KeyVersionRetired,
    #[error("the Transit RSA public key is invalid or has the wrong size")]
    InvalidPublicKey,
    #[error("the Transit RSA public key does not match the configured SPKI digest")]
    PublicKeyMismatch,
    #[error("the Transit RSA signer self-test failed")]
    SelfTest,
    #[error("the Transit RSA verifier policy probe failed")]
    PolicyProbe,
    #[error("the digest must be exactly 64 lowercase hexadecimal ASCII bytes")]
    InvalidDigest,
    #[error("the Transit RSA signature is malformed")]
    InvalidSignature,
    #[error("the Transit RSA signature did not verify")]
    VerificationFailed,
}

fn request_error(fault: TransitRequestFault) -> TransitRsaNoOidError {
    match fault {
        TransitRequestFault::Unavailable => TransitRsaNoOidError::Unavailable,
        TransitRequestFault::Refused => TransitRsaNoOidError::Refused,
        TransitRequestFault::ProviderFailed => TransitRsaNoOidError::ProviderFailed,
        TransitRequestFault::InvalidResponse => TransitRsaNoOidError::InvalidResponse,
    }
}

#[derive(Clone, Copy)]
enum KeyRole {
    Signer,
    Verifier,
}

struct TransitRsaNoOidClient {
    client: reqwest::Client,
    metadata_url: String,
    sign_url: String,
    verify_url: String,
    key_version: u32,
    public_key_sha256: [u8; 32],
    request_timeout: Duration,
    modulus_bytes: usize,
    role: KeyRole,
}

impl TransitRsaNoOidClient {
    async fn initialize(
        config: TransitRsaNoOidKeyConfig,
        role: KeyRole,
    ) -> Result<Self, TransitRsaNoOidError> {
        let client = build_transit_client_no_redirects(&config.socket_path)
            .map_err(|_| TransitRsaNoOidError::Client)?;
        let mut binding = Self {
            client,
            metadata_url: transit_metadata_url(&config.mount_path, &config.key_name),
            sign_url: format!(
                "http://localhost/v1/{}/sign/{}/none",
                config.mount_path, config.key_name
            ),
            verify_url: format!(
                "http://localhost/v1/{}/verify/{}/none",
                config.mount_path, config.key_name
            ),
            key_version: config.key_version,
            public_key_sha256: config.public_key_sha256,
            request_timeout: config.request_timeout,
            modulus_bytes: 0,
            role,
        };
        binding.modulus_bytes = binding.read_and_validate_metadata().await?;
        Ok(binding)
    }

    async fn request_json(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&Value>,
    ) -> Result<Value, TransitRsaNoOidError> {
        send_transit_json(&self.client, self.request_timeout, method, url, body)
            .await
            .map_err(request_error)
    }

    async fn read_and_validate_metadata(&self) -> Result<usize, TransitRsaNoOidError> {
        let document = self
            .request_json(reqwest::Method::GET, &self.metadata_url, None)
            .await?;
        self.validate_metadata(&document)
    }

    async fn revalidate_metadata(&self) -> Result<(), TransitRsaNoOidError> {
        if self.read_and_validate_metadata().await? != self.modulus_bytes {
            return Err(TransitRsaNoOidError::InvalidPublicKey);
        }
        Ok(())
    }

    fn validate_metadata(&self, document: &Value) -> Result<usize, TransitRsaNoOidError> {
        let data = document
            .get("data")
            .and_then(Value::as_object)
            .ok_or(TransitRsaNoOidError::InvalidResponse)?;
        let required_false = ["derived", "exportable", "allow_plaintext_backup"];
        let imported_key = data
            .get("imported_key")
            .and_then(Value::as_bool)
            .ok_or(TransitRsaNoOidError::InvalidResponse)?;
        let role_custody_matches = match self.role {
            KeyRole::Signer => !imported_key,
            KeyRole::Verifier => imported_key,
        };
        if data.get("supports_signing").and_then(Value::as_bool) != Some(true)
            || required_false
                .iter()
                .any(|field| data.get(*field).and_then(Value::as_bool) != Some(false))
            || !role_custody_matches
        {
            return Err(TransitRsaNoOidError::UnsafeCustody);
        }

        let latest_version = metadata_u32(data, "latest_version")?;
        if self.key_version > latest_version {
            return Err(TransitRsaNoOidError::KeyVersionNotCreated);
        }
        let minimum_field = match self.role {
            KeyRole::Signer => "min_encryption_version",
            KeyRole::Verifier => "min_decryption_version",
        };
        let minimum_version = metadata_u32(data, minimum_field)?;
        if minimum_version != 0 && self.key_version < minimum_version {
            return Err(TransitRsaNoOidError::KeyVersionRetired);
        }

        let version = self.key_version.to_string();
        let public_pem = data
            .get("keys")
            .and_then(Value::as_object)
            .and_then(|keys| keys.get(&version))
            .and_then(Value::as_object)
            .and_then(|key| key.get("public_key"))
            .and_then(Value::as_str)
            .ok_or(TransitRsaNoOidError::InvalidPublicKey)?;
        let spki_der = decode_public_key_pem(public_pem)?;
        let actual_spki_sha256: [u8; 32] = Sha256::digest(spki_der.as_slice()).into();
        if actual_spki_sha256 != self.public_key_sha256 {
            return Err(TransitRsaNoOidError::PublicKeyMismatch);
        }
        let key = RsaPublicKey::from_der(spki_der.as_slice())
            .map_err(|_| TransitRsaNoOidError::InvalidPublicKey)?;
        let pkcs1 = pkcs1::RsaPublicKey::from_der(key.as_ref())
            .map_err(|_| TransitRsaNoOidError::InvalidPublicKey)?;
        let modulus = pkcs1.modulus.as_bytes();
        let modulus_bits = exact_bit_length(modulus)?;
        let metadata_bits = match data.get("type").and_then(Value::as_str) {
            Some("rsa-2048") => 2048,
            Some("rsa-3072") => 3072,
            Some("rsa-4096") => 4096,
            _ => return Err(TransitRsaNoOidError::InvalidPublicKey),
        };
        if modulus_bits != metadata_bits {
            return Err(TransitRsaNoOidError::InvalidPublicKey);
        }
        Ok(modulus.len())
    }

    async fn request_signature(
        &self,
        input: &[u8; 64],
    ) -> Result<TransitRsaNoOidSignature, TransitRsaNoOidError> {
        validate_digest(input)?;
        self.revalidate_metadata().await?;
        let body = json!({
            "input": STANDARD.encode(input),
            "key_version": self.key_version,
            "prehashed": true,
            "signature_algorithm": "pkcs1v15",
        });
        let mut document = self
            .request_json(reqwest::Method::POST, &self.sign_url, Some(&body))
            .await?;
        let signature = document
            .get_mut("data")
            .and_then(Value::as_object_mut)
            .and_then(|data| data.get_mut("signature"))
            .and_then(|value| match value {
                Value::String(signature) => Some(signature),
                _ => None,
            })
            .ok_or(TransitRsaNoOidError::InvalidSignature)?;
        let signature = Zeroizing::new(std::mem::take(signature));
        let prefix = format!("vault:v{}:", self.key_version);
        let encoded = signature
            .strip_prefix(&prefix)
            .ok_or(TransitRsaNoOidError::InvalidSignature)?;
        let decoded = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| TransitRsaNoOidError::InvalidSignature)?,
        );
        if decoded.len() != self.modulus_bytes || STANDARD.encode(decoded.as_slice()) != encoded {
            return Err(TransitRsaNoOidError::InvalidSignature);
        }
        Ok(TransitRsaNoOidSignature(decoded))
    }

    async fn request_verification(
        &self,
        input: &[u8; 64],
        signature: &[u8],
    ) -> Result<bool, TransitRsaNoOidError> {
        validate_digest(input)?;
        if signature.len() != self.modulus_bytes {
            return Err(TransitRsaNoOidError::InvalidSignature);
        }
        self.revalidate_metadata().await?;
        let body = json!({
            "input": STANDARD.encode(input),
            "prehashed": true,
            "signature": format!(
                "vault:v{}:{}",
                self.key_version,
                STANDARD.encode(signature)
            ),
            "signature_algorithm": "pkcs1v15",
        });
        let document = self
            .request_json(reqwest::Method::POST, &self.verify_url, Some(&body))
            .await?;
        document
            .get("data")
            .and_then(|data| data.get("valid"))
            .and_then(Value::as_bool)
            .ok_or(TransitRsaNoOidError::InvalidResponse)
    }
}

/// Service-created raw RSA signer reached through a trusted local proxy.
pub struct TransitRsaNoOidSigner(TransitRsaNoOidClient);

impl fmt::Debug for TransitRsaNoOidSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitRsaNoOidSigner")
            .finish_non_exhaustive()
    }
}

impl TransitRsaNoOidSigner {
    /// Validate the service-created key and prove sign plus pinned-key verify.
    ///
    /// # Errors
    ///
    /// Returns a redacted provider, custody, key-binding, or self-test error.
    pub async fn initialize(
        config: TransitRsaNoOidKeyConfig,
    ) -> Result<Self, TransitRsaNoOidError> {
        let client = TransitRsaNoOidClient::initialize(config, KeyRole::Signer).await?;
        let signature = client
            .request_signature(SELF_TEST_DIGEST)
            .await
            .map_err(|_| TransitRsaNoOidError::SelfTest)?;
        let valid = client
            .request_verification(SELF_TEST_DIGEST, signature.as_bytes())
            .await
            .map_err(|_| TransitRsaNoOidError::SelfTest)?;
        if !valid {
            return Err(TransitRsaNoOidError::SelfTest);
        }
        Ok(Self(client))
    }

    /// Sign one 64-byte lowercase hexadecimal digest string and verify the
    /// provider result with the same pinned key before releasing it.
    ///
    /// # Errors
    ///
    /// Returns a redacted validation, provider, key-binding, signature, or
    /// verification error.
    pub async fn sign_digest_hex(
        &self,
        input: &[u8; 64],
    ) -> Result<TransitRsaNoOidSignature, TransitRsaNoOidError> {
        let signature = self.0.request_signature(input).await?;
        if !self
            .0
            .request_verification(input, signature.as_bytes())
            .await?
        {
            return Err(TransitRsaNoOidError::VerificationFailed);
        }
        Ok(signature)
    }
}

/// Operator-imported public-key verifier reached through a trusted local proxy.
pub struct TransitRsaNoOidVerifier(TransitRsaNoOidClient);

impl fmt::Debug for TransitRsaNoOidVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitRsaNoOidVerifier")
            .finish_non_exhaustive()
    }
}

impl TransitRsaNoOidVerifier {
    /// Validate the imported public key and prove the verify endpoint rejects
    /// a fixed, deliberately invalid modulus-width signature before serving.
    ///
    /// # Errors
    ///
    /// Returns a redacted provider, custody, key-binding, or policy-probe
    /// error.
    pub async fn initialize(
        config: TransitRsaNoOidKeyConfig,
    ) -> Result<Self, TransitRsaNoOidError> {
        let client = TransitRsaNoOidClient::initialize(config, KeyRole::Verifier).await?;
        let invalid_signature = Zeroizing::new(vec![0_u8; client.modulus_bytes]);
        match client
            .request_verification(SELF_TEST_DIGEST, &invalid_signature)
            .await
        {
            Ok(false) => Ok(Self(client)),
            Ok(true) | Err(_) => Err(TransitRsaNoOidError::PolicyProbe),
        }
    }

    /// Verify a raw modulus-width signature over one lowercase hex digest.
    ///
    /// # Errors
    ///
    /// Returns a redacted validation, provider, key-binding, signature, or
    /// verification error.
    pub async fn verify_digest_hex(
        &self,
        input: &[u8; 64],
        signature: &[u8],
    ) -> Result<(), TransitRsaNoOidError> {
        if self.0.request_verification(input, signature).await? {
            Ok(())
        } else {
            Err(TransitRsaNoOidError::VerificationFailed)
        }
    }
}

fn metadata_u32(
    data: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<u32, TransitRsaNoOidError> {
    data.get(field)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(TransitRsaNoOidError::InvalidResponse)
}

fn decode_public_key_pem(pem: &str) -> Result<Zeroizing<Vec<u8>>, TransitRsaNoOidError> {
    let (label, document) =
        p256::pkcs8::Document::from_pem(pem).map_err(|_| TransitRsaNoOidError::InvalidPublicKey)?;
    if label != "PUBLIC KEY" {
        return Err(TransitRsaNoOidError::InvalidPublicKey);
    }
    let _: p256::pkcs8::SubjectPublicKeyInfoRef<'_> = document
        .decode_msg()
        .map_err(|_| TransitRsaNoOidError::InvalidPublicKey)?;
    Ok(Zeroizing::new(document.into_vec()))
}

fn exact_bit_length(bytes: &[u8]) -> Result<usize, TransitRsaNoOidError> {
    let first = *bytes
        .first()
        .ok_or(TransitRsaNoOidError::InvalidPublicKey)?;
    if first == 0 {
        return Err(TransitRsaNoOidError::InvalidPublicKey);
    }
    Ok((bytes.len() - 1) * 8 + (8 - first.leading_zeros() as usize))
}

fn validate_digest(input: &[u8; 64]) -> Result<(), TransitRsaNoOidError> {
    if input
        .iter()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(TransitRsaNoOidError::InvalidDigest)
    }
}

#[cfg(all(test, unix, feature = "transit"))]
mod tests {
    use std::sync::OnceLock;
    use std::time::Duration;

    use aws_lc_rs::encoding::{AsDer as _, PublicKeyX509Der};
    use aws_lc_rs::signature::KeyPair as _;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde_json::{json, Value};
    use sha2::{Digest as _, Sha256};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::UnixListener;

    use super::{
        TransitRsaNoOidError, TransitRsaNoOidKeyConfig, TransitRsaNoOidSigner,
        TransitRsaNoOidVerifier,
    };
    use crate::transit_mock::{spawn_transit_mock, transit_reply, MockTransitReply};
    use crate::{generate_private_jwk, rsa_private_key, GeneratedKeyAlgorithm};

    const TIMEOUT: Duration = Duration::from_secs(2);
    const MOUNT: &str = "transit";
    const KEY: &str = "mifos-request";
    const VERSION: u32 = 7;
    const METADATA_PATH: &str = "/v1/transit/keys/mifos-request";
    const SIGN_PATH: &str = "/v1/transit/sign/mifos-request/none";
    const VERIFY_PATH: &str = "/v1/transit/verify/mifos-request/none";
    const DUMMY_DIGEST: &[u8; 64] =
        b"0000000000000000000000000000000000000000000000000000000000000000";
    const DIGEST: &[u8; 64] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct RsaFixture {
        public_pem: String,
        public_spki: Vec<u8>,
        public_spki_sha256: [u8; 32],
        signature: Vec<u8>,
    }

    fn rsa_fixture() -> &'static RsaFixture {
        static FIXTURE: OnceLock<RsaFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let private =
                generate_private_jwk(GeneratedKeyAlgorithm::Rs384).expect("generate test RSA key");
            let key_pair = rsa_private_key(&private).expect("load generated RSA key");
            let spki: PublicKeyX509Der<'_> = key_pair
                .public_key()
                .as_der()
                .expect("encode test RSA SPKI");
            let spki = spki.as_ref();
            let encoded = STANDARD.encode(spki);
            let mut public_pem = String::from("-----BEGIN PUBLIC KEY-----\n");
            for line in encoded.as_bytes().chunks(64) {
                public_pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
                public_pem.push('\n');
            }
            public_pem.push_str("-----END PUBLIC KEY-----\n");
            RsaFixture {
                public_pem,
                public_spki: spki.to_vec(),
                public_spki_sha256: Sha256::digest(spki).into(),
                signature: vec![0x5a; 256],
            }
        })
    }

    fn metadata(imported_key: bool) -> Value {
        json!({
            "data": {
                "type": "rsa-2048",
                "derived": false,
                "exportable": false,
                "allow_plaintext_backup": false,
                "supports_signing": true,
                "latest_version": VERSION,
                "min_encryption_version": 1,
                "min_decryption_version": 1,
                "imported_key": imported_key,
                "keys": {
                    VERSION.to_string(): {
                        "public_key": rsa_fixture().public_pem.as_str(),
                    }
                }
            }
        })
    }

    fn config(socket_path: std::path::PathBuf) -> TransitRsaNoOidKeyConfig {
        TransitRsaNoOidKeyConfig::new(
            socket_path,
            MOUNT.to_owned(),
            KEY.to_owned(),
            VERSION,
            rsa_fixture().public_spki_sha256,
            TIMEOUT,
        )
        .expect("fixture config validates")
    }

    fn sign_body(input: &[u8; 64]) -> Value {
        json!({
            "input": STANDARD.encode(input),
            "key_version": VERSION,
            "prehashed": true,
            "signature_algorithm": "pkcs1v15",
        })
    }

    fn verify_body(input: &[u8; 64], signature: &[u8]) -> Value {
        json!({
            "input": STANDARD.encode(input),
            "prehashed": true,
            "signature": format!("vault:v{VERSION}:{}", STANDARD.encode(signature)),
            "signature_algorithm": "pkcs1v15",
        })
    }

    fn signer_startup_replies() -> Vec<crate::transit_mock::MockTransitReply> {
        vec![
            transit_reply("GET", METADATA_PATH, None, metadata(false)),
            transit_reply("GET", METADATA_PATH, None, metadata(false)),
            transit_reply(
                "POST",
                SIGN_PATH,
                Some(sign_body(DUMMY_DIGEST)),
                json!({
                    "data": {
                        "signature": format!(
                            "vault:v{VERSION}:{}",
                            STANDARD.encode(&rsa_fixture().signature)
                        )
                    }
                }),
            ),
            transit_reply("GET", METADATA_PATH, None, metadata(false)),
            transit_reply(
                "POST",
                VERIFY_PATH,
                Some(verify_body(DUMMY_DIGEST, &rsa_fixture().signature)),
                json!({"data": {"valid": true}}),
            ),
        ]
    }

    fn verifier_startup_replies() -> Vec<crate::transit_mock::MockTransitReply> {
        vec![
            transit_reply("GET", METADATA_PATH, None, metadata(true)),
            transit_reply("GET", METADATA_PATH, None, metadata(true)),
            transit_reply(
                "POST",
                VERIFY_PATH,
                Some(verify_body(DUMMY_DIGEST, &[0_u8; 256])),
                json!({"data": {"valid": false}}),
            ),
        ]
    }

    #[tokio::test]
    async fn signer_initialization_pins_exact_metadata_and_no_oid_wire_contract() {
        let (directory, socket_path, server) = spawn_transit_mock(signer_startup_replies());
        TransitRsaNoOidSigner::initialize(config(socket_path))
            .await
            .expect("signer initializes");
        server.await.expect("mock Transit server completed");
        drop(directory);
    }

    #[tokio::test]
    async fn verifier_initialization_requires_imported_key_and_probes_false_verification() {
        let (directory, socket_path, server) = spawn_transit_mock(verifier_startup_replies());
        TransitRsaNoOidVerifier::initialize(config(socket_path))
            .await
            .expect("verifier initializes");
        server.await.expect("mock Transit server completed");
        drop(directory);
    }

    #[tokio::test]
    async fn signer_releases_only_a_canonical_signature_the_pinned_key_verifies() {
        let mut replies = signer_startup_replies();
        replies.push(transit_reply("GET", METADATA_PATH, None, metadata(false)));
        replies.push(transit_reply(
            "POST",
            SIGN_PATH,
            Some(sign_body(DIGEST)),
            json!({
                "data": {
                    "signature": format!(
                        "vault:v{VERSION}:{}",
                        STANDARD.encode(&rsa_fixture().signature)
                    )
                }
            }),
        ));
        replies.push(transit_reply("GET", METADATA_PATH, None, metadata(false)));
        replies.push(transit_reply(
            "POST",
            VERIFY_PATH,
            Some(verify_body(DIGEST, &rsa_fixture().signature)),
            json!({"data": {"valid": true}}),
        ));
        let (directory, socket_path, server) = spawn_transit_mock(replies);
        let signer = TransitRsaNoOidSigner::initialize(config(socket_path))
            .await
            .expect("signer initializes");
        let signature = signer.sign_digest_hex(DIGEST).await.expect("digest signs");
        assert_eq!(signature.as_bytes(), rsa_fixture().signature);
        server.await.expect("mock Transit server completed");
        drop(directory);
    }

    #[tokio::test]
    async fn signer_refuses_a_provider_signature_that_the_pinned_key_does_not_verify() {
        let mut replies = signer_startup_replies();
        replies.push(transit_reply("GET", METADATA_PATH, None, metadata(false)));
        replies.push(transit_reply(
            "POST",
            SIGN_PATH,
            Some(sign_body(DIGEST)),
            json!({
                "data": {
                    "signature": format!(
                        "vault:v{VERSION}:{}",
                        STANDARD.encode(&rsa_fixture().signature)
                    )
                }
            }),
        ));
        replies.push(transit_reply("GET", METADATA_PATH, None, metadata(false)));
        replies.push(transit_reply(
            "POST",
            VERIFY_PATH,
            Some(verify_body(DIGEST, &rsa_fixture().signature)),
            json!({"data": {"valid": false}}),
        ));
        let (directory, socket_path, server) = spawn_transit_mock(replies);
        let signer = TransitRsaNoOidSigner::initialize(config(socket_path))
            .await
            .expect("signer initializes");
        let error = signer
            .sign_digest_hex(DIGEST)
            .await
            .err()
            .expect("unverified signature is withheld");
        assert_eq!(error, TransitRsaNoOidError::VerificationFailed);
        server.await.expect("mock Transit server completed");
        drop(directory);
    }

    #[tokio::test]
    async fn verifier_sends_the_exact_wrapped_signature_and_requires_true() {
        let mut replies = verifier_startup_replies();
        replies.push(transit_reply("GET", METADATA_PATH, None, metadata(true)));
        replies.push(transit_reply(
            "POST",
            VERIFY_PATH,
            Some(verify_body(DIGEST, &rsa_fixture().signature)),
            json!({"data": {"valid": true}}),
        ));
        replies.push(transit_reply("GET", METADATA_PATH, None, metadata(true)));
        replies.push(transit_reply(
            "POST",
            VERIFY_PATH,
            Some(verify_body(DIGEST, &rsa_fixture().signature)),
            json!({"data": {"valid": false}}),
        ));
        let (directory, socket_path, server) = spawn_transit_mock(replies);
        let verifier = TransitRsaNoOidVerifier::initialize(config(socket_path))
            .await
            .expect("verifier initializes");
        verifier
            .verify_digest_hex(DIGEST, &rsa_fixture().signature)
            .await
            .expect("valid signature verifies");
        assert_eq!(
            verifier
                .verify_digest_hex(DIGEST, &rsa_fixture().signature)
                .await,
            Err(TransitRsaNoOidError::VerificationFailed)
        );
        server.await.expect("mock Transit server completed");
        drop(directory);
    }

    #[tokio::test]
    async fn replaced_named_key_is_refused_before_sign_or_verify() {
        let mut replacement_spki = rsa_fixture().public_spki.clone();
        *replacement_spki.last_mut().expect("SPKI has an exponent") ^= 2;
        let replacement_pem = public_key_pem(&replacement_spki);
        let mut replaced_signer = metadata(false);
        replaced_signer["data"]["keys"][VERSION.to_string()]["public_key"] =
            json!(replacement_pem.as_str());
        let mut signer_replies = signer_startup_replies();
        signer_replies.push(transit_reply("GET", METADATA_PATH, None, replaced_signer));
        let (directory, socket_path, server) = spawn_transit_mock(signer_replies);
        let signer = TransitRsaNoOidSigner::initialize(config(socket_path))
            .await
            .expect("signer initializes");
        let error = signer
            .sign_digest_hex(DIGEST)
            .await
            .err()
            .expect("replaced key refuses before sign");
        assert_eq!(error, TransitRsaNoOidError::PublicKeyMismatch);
        server.await.expect("mock Transit server completed");
        drop(directory);

        let mut replaced_verifier = metadata(true);
        replaced_verifier["data"]["keys"][VERSION.to_string()]["public_key"] =
            json!(replacement_pem.as_str());
        let mut verifier_replies = verifier_startup_replies();
        verifier_replies.push(transit_reply("GET", METADATA_PATH, None, replaced_verifier));
        let (directory, socket_path, server) = spawn_transit_mock(verifier_replies);
        let verifier = TransitRsaNoOidVerifier::initialize(config(socket_path))
            .await
            .expect("verifier initializes");
        let error = verifier
            .verify_digest_hex(DIGEST, &rsa_fixture().signature)
            .await
            .expect_err("replaced key refuses before verify");
        assert_eq!(error, TransitRsaNoOidError::PublicKeyMismatch);
        server.await.expect("mock Transit server completed");
        drop(directory);
    }

    #[tokio::test]
    async fn rsa_primitive_refuses_redirects() {
        let directory = tempfile::tempdir().expect("temporary Transit directory");
        let socket_path = directory.path().join("transit.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind redirect mock");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept metadata request");
            let mut request = vec![0_u8; 4096];
            let read = stream
                .read(&mut request)
                .await
                .expect("read metadata request");
            let request = std::str::from_utf8(&request[..read]).expect("request is UTF-8");
            assert!(request.starts_with(&format!("GET {METADATA_PATH} ")));
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://localhost/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write redirect");
        });
        let error = TransitRsaNoOidSigner::initialize(config(socket_path))
            .await
            .expect_err("redirect is not followed");
        assert_eq!(error, TransitRsaNoOidError::Refused);
        server.await.expect("redirect mock completed");
        drop(directory);
    }

    #[tokio::test]
    async fn rsa_primitive_bounds_provider_time_and_response_bytes() {
        let delayed = MockTransitReply {
            method: "GET",
            path: METADATA_PATH,
            body: None,
            status: 200,
            response: serde_json::to_vec(&metadata(false)).expect("metadata JSON"),
            delay: Duration::from_millis(50),
        };
        let (directory, socket_path, server) = spawn_transit_mock(vec![delayed]);
        let short_timeout = TransitRsaNoOidKeyConfig::new(
            socket_path,
            MOUNT.to_owned(),
            KEY.to_owned(),
            VERSION,
            rsa_fixture().public_spki_sha256,
            Duration::from_millis(5),
        )
        .expect("short bounded timeout validates");
        let error = TransitRsaNoOidSigner::initialize(short_timeout)
            .await
            .expect_err("slow metadata times out");
        assert_eq!(error, TransitRsaNoOidError::Unavailable);
        server.await.expect("slow mock completed");
        drop(directory);

        let oversized = MockTransitReply {
            method: "GET",
            path: METADATA_PATH,
            body: None,
            status: 200,
            response: vec![b'x'; crate::MAX_TRANSIT_RESPONSE_BYTES + 1],
            delay: Duration::ZERO,
        };
        let (directory, socket_path, server) = spawn_transit_mock(vec![oversized]);
        let error = TransitRsaNoOidSigner::initialize(config(socket_path))
            .await
            .expect_err("oversized metadata rejects");
        assert_eq!(error, TransitRsaNoOidError::InvalidResponse);
        server.await.expect("oversized mock completed");
        drop(directory);
    }

    #[tokio::test]
    async fn signer_refuses_unsafe_custody_role_version_and_key_binding() {
        let mut cases = Vec::new();
        for field in ["derived", "exportable", "allow_plaintext_backup"] {
            let mut document = metadata(false);
            document["data"][field] = json!(true);
            cases.push((document, TransitRsaNoOidError::UnsafeCustody));
        }
        let mut imported = metadata(false);
        imported["data"]["imported_key"] = json!(true);
        cases.push((imported, TransitRsaNoOidError::UnsafeCustody));
        let mut wrong_type = metadata(false);
        wrong_type["data"]["type"] = json!("rsa-3072");
        cases.push((wrong_type, TransitRsaNoOidError::InvalidPublicKey));
        let mut retired = metadata(false);
        retired["data"]["min_encryption_version"] = json!(8);
        cases.push((retired, TransitRsaNoOidError::KeyVersionRetired));
        let mut future = metadata(false);
        future["data"]["latest_version"] = json!(6);
        cases.push((future, TransitRsaNoOidError::KeyVersionNotCreated));

        for (document, expected) in cases {
            let (directory, socket_path, server) =
                spawn_transit_mock(vec![transit_reply("GET", METADATA_PATH, None, document)]);
            let error = TransitRsaNoOidSigner::initialize(config(socket_path))
                .await
                .expect_err("unsafe metadata rejects");
            assert_eq!(error, expected);
            server.await.expect("mock Transit server completed");
            drop(directory);
        }

        let (directory, socket_path, server) = spawn_transit_mock(vec![transit_reply(
            "GET",
            METADATA_PATH,
            None,
            metadata(false),
        )]);
        let mut wrong_hash = rsa_fixture().public_spki_sha256;
        wrong_hash[0] ^= 1;
        let wrong_config = TransitRsaNoOidKeyConfig::new(
            socket_path,
            MOUNT.to_owned(),
            KEY.to_owned(),
            VERSION,
            wrong_hash,
            TIMEOUT,
        )
        .expect("hash shape validates");
        let error = TransitRsaNoOidSigner::initialize(wrong_config)
            .await
            .expect_err("wrong hash rejects");
        assert_eq!(error, TransitRsaNoOidError::PublicKeyMismatch);
        server.await.expect("mock Transit server completed");
        drop(directory);
    }

    #[tokio::test]
    async fn verifier_refuses_service_created_or_signing_version_retired_metadata() {
        let mut retired = metadata(true);
        retired["data"]["min_decryption_version"] = json!(8);
        for (document, expected) in [
            (metadata(false), TransitRsaNoOidError::UnsafeCustody),
            (retired, TransitRsaNoOidError::KeyVersionRetired),
        ] {
            let (directory, socket_path, server) =
                spawn_transit_mock(vec![transit_reply("GET", METADATA_PATH, None, document)]);
            let error = TransitRsaNoOidVerifier::initialize(config(socket_path))
                .await
                .expect_err("wrong verifier metadata rejects");
            assert_eq!(error, expected);
            server.await.expect("mock Transit server completed");
            drop(directory);
        }
    }

    #[tokio::test]
    async fn invalid_digest_and_signature_length_fail_before_provider_access() {
        let (directory, socket_path, server) = spawn_transit_mock(signer_startup_replies());
        let signer = TransitRsaNoOidSigner::initialize(config(socket_path))
            .await
            .expect("signer initializes");
        let mut uppercase = *DIGEST;
        uppercase[10] = b'A';
        let error = signer
            .sign_digest_hex(&uppercase)
            .await
            .err()
            .expect("uppercase digest rejects");
        assert_eq!(error, TransitRsaNoOidError::InvalidDigest);
        server.await.expect("mock Transit server completed");
        drop(directory);

        let (directory, socket_path, server) = spawn_transit_mock(verifier_startup_replies());
        let verifier = TransitRsaNoOidVerifier::initialize(config(socket_path))
            .await
            .expect("verifier initializes");
        assert_eq!(
            verifier.verify_digest_hex(DIGEST, &[0_u8; 255]).await,
            Err(TransitRsaNoOidError::InvalidSignature)
        );
        server.await.expect("mock Transit server completed");
        drop(directory);
    }

    #[tokio::test]
    async fn signer_rejects_bad_prefix_length_and_noncanonical_base64() {
        let cases = [
            format!("vault:v8:{}", STANDARD.encode(&rsa_fixture().signature)),
            format!("vault:v{VERSION}:AAAA"),
            format!(
                "vault:v{VERSION}:{}",
                STANDARD.encode([0xff_u8; 256]).replace('/', "_")
            ),
            format!(
                "vault:v{VERSION}:{}",
                STANDARD
                    .encode(&rsa_fixture().signature)
                    .trim_end_matches('=')
            ),
        ];
        for provider_signature in cases {
            let mut replies = signer_startup_replies();
            replies.push(transit_reply("GET", METADATA_PATH, None, metadata(false)));
            replies.push(transit_reply(
                "POST",
                SIGN_PATH,
                Some(sign_body(DIGEST)),
                json!({"data": {"signature": provider_signature}}),
            ));
            let (directory, socket_path, server) = spawn_transit_mock(replies);
            let signer = TransitRsaNoOidSigner::initialize(config(socket_path))
                .await
                .expect("signer initializes");
            let error = signer
                .sign_digest_hex(DIGEST)
                .await
                .err()
                .expect("malformed provider signature rejects");
            assert_eq!(error, TransitRsaNoOidError::InvalidSignature);
            server.await.expect("mock Transit server completed");
            drop(directory);
        }
    }

    #[tokio::test]
    async fn false_or_malformed_verify_response_fails_closed_without_raw_json() {
        const CANARY: &str = "PRIVATE_PROVIDER_DIAGNOSTIC_CANARY";
        for (response, expected) in [
            (
                json!({"data": {"valid": false}}),
                TransitRsaNoOidError::VerificationFailed,
            ),
            (
                json!({"data": {"valid": "true", "detail": CANARY}}),
                TransitRsaNoOidError::InvalidResponse,
            ),
        ] {
            let mut replies = verifier_startup_replies();
            replies.push(transit_reply("GET", METADATA_PATH, None, metadata(true)));
            replies.push(transit_reply(
                "POST",
                VERIFY_PATH,
                Some(verify_body(DIGEST, &rsa_fixture().signature)),
                response,
            ));
            let (directory, socket_path, server) = spawn_transit_mock(replies);
            let verifier = TransitRsaNoOidVerifier::initialize(config(socket_path))
                .await
                .expect("verifier initializes");
            let error = verifier
                .verify_digest_hex(DIGEST, &rsa_fixture().signature)
                .await
                .expect_err("verification must fail closed");
            assert_eq!(error, expected);
            assert!(!error.to_string().contains(CANARY));
            server.await.expect("mock Transit server completed");
            drop(directory);
        }
    }

    #[tokio::test]
    async fn released_mifos_response_vector_uses_exact_no_oid_verify_wire() {
        const FIXTURE: &[u8] =
            include_bytes!("../tests/fixtures/mifos-bulk-v1.12.1-response-signatures.json");
        const FIXTURE_SHA256: &str =
            "ed24b1b3e0b580445751a23b9283994e8052534a2e3350bafed96ecff214fa98";

        assert_eq!(hex_lower(&Sha256::digest(FIXTURE)), FIXTURE_SHA256);
        let vector: Value = serde_json::from_slice(FIXTURE).expect("released vector JSON");
        assert_eq!(
            fixture_string(&vector, "sourceImage"),
            "docker.io/openmf/ph-ee-bulk-processor@sha256:6d58a33751d458fc96b7fa6bb3388456b17b81ad9d61cadd057a825751472c34"
        );
        assert_eq!(fixture_string(&vector, "tenantHeader"), "Platform-TenantId");
        assert_eq!(fixture_string(&vector, "tenant"), "pilot");

        let spki = STANDARD
            .decode(fixture_string(&vector, "publicKeySpkiBase64"))
            .expect("fixture SPKI base64");
        assert_eq!(
            hex_lower(&Sha256::digest(&spki)),
            fixture_string(&vector, "publicKeySpkiSha256")
        );
        let public_pem = public_key_pem(&spki);
        let public_key_sha256: [u8; 32] = Sha256::digest(&spki).into();
        let signature = STANDARD
            .decode(fixture_string(&vector, "signatureBase64"))
            .expect("fixture raw signature base64");
        let rs256_signature = STANDARD
            .decode(fixture_string(&vector, "rs256SignatureBase64"))
            .expect("fixture RS256 signature base64");
        assert_eq!(signature.len(), 256);
        assert_eq!(rs256_signature.len(), 256);

        let accepted = digest_bytes(fixture_string(&vector, "bodyOnlySha3Hex"));
        let altered_header = digest_bytes(fixture_string(&vector, "uppercaseSha3Hex"));
        let changed_body = sha3_hex(fixture_string(&vector, "changedBody"));
        assert_eq!(sha3_hex(fixture_string(&vector, "body")), accepted);
        assert_ne!(accepted, altered_header);
        assert_ne!(accepted, changed_body);

        let metadata = || {
            json!({
                "data": {
                    "type": "rsa-2048",
                    "derived": false,
                    "exportable": false,
                    "allow_plaintext_backup": false,
                    "supports_signing": true,
                    "latest_version": VERSION,
                    "min_encryption_version": 1,
                    "min_decryption_version": 1,
                    "imported_key": true,
                    "keys": {VERSION.to_string(): {"public_key": public_pem.as_str()}}
                }
            })
        };
        let mut replies = vec![
            transit_reply("GET", METADATA_PATH, None, metadata()),
            transit_reply("GET", METADATA_PATH, None, metadata()),
            transit_reply(
                "POST",
                VERIFY_PATH,
                Some(verify_body(DUMMY_DIGEST, &[0_u8; 256])),
                json!({"data": {"valid": false}}),
            ),
        ];
        for (input, candidate, valid) in [
            (accepted, signature.as_slice(), true),
            (altered_header, signature.as_slice(), false),
            (changed_body, signature.as_slice(), false),
            (accepted, rs256_signature.as_slice(), false),
        ] {
            replies.push(transit_reply("GET", METADATA_PATH, None, metadata()));
            replies.push(transit_reply(
                "POST",
                VERIFY_PATH,
                Some(verify_body(&input, candidate)),
                json!({"data": {"valid": valid}}),
            ));
        }

        let (directory, socket_path, server) = spawn_transit_mock(replies);
        let config = TransitRsaNoOidKeyConfig::new(
            socket_path,
            MOUNT.to_owned(),
            KEY.to_owned(),
            VERSION,
            public_key_sha256,
            TIMEOUT,
        )
        .expect("released vector config validates");
        let verifier = TransitRsaNoOidVerifier::initialize(config)
            .await
            .expect("released vector verifier initializes");
        verifier
            .verify_digest_hex(&accepted, &signature)
            .await
            .expect("released raw signature verifies");
        for (input, candidate) in [
            (altered_header, signature.as_slice()),
            (changed_body, signature.as_slice()),
            (accepted, rs256_signature.as_slice()),
        ] {
            assert_eq!(
                verifier.verify_digest_hex(&input, candidate).await,
                Err(TransitRsaNoOidError::VerificationFailed)
            );
        }
        server.await.expect("released-vector mock completed");
        drop(directory);
    }

    #[test]
    fn configuration_refuses_unbounded_or_unsafe_bindings_without_identifiers_in_errors() {
        let cases = [
            TransitRsaNoOidKeyConfig::new(
                "relative.sock".into(),
                MOUNT.to_owned(),
                KEY.to_owned(),
                VERSION,
                rsa_fixture().public_spki_sha256,
                TIMEOUT,
            ),
            TransitRsaNoOidKeyConfig::new(
                "/run/transit.sock".into(),
                "../transit".to_owned(),
                KEY.to_owned(),
                VERSION,
                rsa_fixture().public_spki_sha256,
                TIMEOUT,
            ),
            TransitRsaNoOidKeyConfig::new(
                "/run/transit.sock".into(),
                MOUNT.to_owned(),
                KEY.to_owned(),
                0,
                rsa_fixture().public_spki_sha256,
                TIMEOUT,
            ),
            TransitRsaNoOidKeyConfig::new(
                "/run/transit.sock".into(),
                MOUNT.to_owned(),
                KEY.to_owned(),
                VERSION,
                rsa_fixture().public_spki_sha256,
                Duration::from_secs(31),
            ),
        ];
        for result in cases {
            let error = result.expect_err("invalid config rejects");
            assert_eq!(error, TransitRsaNoOidError::InvalidConfiguration);
            let rendered = error.to_string();
            assert!(!rendered.contains("transit.sock"));
            assert!(!rendered.contains(KEY));
        }
    }

    fn fixture_string<'a>(vector: &'a Value, field: &str) -> &'a str {
        vector
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("released vector string {field}"))
    }

    fn digest_bytes(value: &str) -> [u8; 64] {
        value
            .as_bytes()
            .try_into()
            .expect("released digest is 64 ASCII bytes")
    }

    fn sha3_hex(value: &str) -> [u8; 64] {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA3_256, value.as_bytes());
        let encoded = hex_lower(digest.as_ref());
        encoded
            .as_bytes()
            .try_into()
            .expect("SHA3-256 hex is 64 ASCII bytes")
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    fn public_key_pem(spki: &[u8]) -> String {
        let encoded = STANDARD.encode(spki);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        pem
    }
}
