// SPDX-License-Identifier: Apache-2.0
//! Crypto primitives shared by Registry Platform consumers.

use async_trait::async_trait;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as AwsRsaKeyPair, PublicKeyComponents as AwsRsaPublicKeyComponents};
use aws_lc_rs::signature::{
    EcdsaKeyPair, RsaParameters, RsaSignatureEncoding, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384,
};
#[cfg(feature = "transit")]
use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use hmac::{Hmac, KeyInit, Mac};
use p256::ecdsa::{
    signature::Verifier as _, Signature as P256Signature, VerifyingKey as P256VerifyingKey,
};
#[cfg(feature = "transit")]
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
#[cfg(feature = "transit")]
use p256::pkcs8::DecodePublicKey as _;
#[cfg(feature = "transit")]
use p256::PublicKey as P256PublicKey;
use pkcs1::{der::asn1::UintRef, der::SecretDocument, RsaPrivateKey as Pkcs1RsaPrivateKey};
pub use registry_platform_canonical_json::{
    canonicalize_json, parse_json_strict, JcsError, StrictJsonError,
};
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::IpAddr;
#[cfg(feature = "transit")]
use std::path::PathBuf;
#[cfg(feature = "transit")]
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
#[cfg(feature = "transit")]
use std::time::Duration;
use thiserror::Error;
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

/// Compute a SHA-256 digest with an explicit, caller-owned domain prefix.
///
/// Domains must be fixed protocol constants. This helper exists so product
/// consumers can verify canonical public-contract identities without gaining
/// access to opaque transport bodies.
#[must_use]
pub fn domain_separated_sha256(domain: &[u8], canonical_payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical_payload);
    hasher.finalize().into()
}

/// Maximum raw JSON bytes accepted by the JWK parsing boundaries.
pub const MAX_JWK_JSON_BYTES: usize = 64 * 1024;
const MAX_DID_JWK_IDENTIFIER_BYTES: usize = MAX_JWK_JSON_BYTES.div_ceil(3) * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// Ed25519 EdDSA signatures using OKP/Ed25519 JWKs.
    EdDsa,
    /// ECDSA over P-256 with SHA-256 (ES256) signatures using EC/P-256 JWKs.
    Es256,
    /// RSASSA-PKCS1-v1_5 with SHA-256 (RS256) signatures using RSA JWKs.
    Rs256,
    /// ECDSA over P-384 with SHA-384 (ES384) signatures using EC/P-384 JWKs.
    Es384,
    /// RSASSA-PKCS1-v1_5 with SHA-384 (RS384) signatures using RSA JWKs.
    Rs384,
}

impl SigningAlgorithm {
    /// The JWS `alg` header value naming this algorithm.
    #[must_use]
    pub const fn jwa_name(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
            Self::Es384 => "ES384",
            Self::Rs384 => "RS384",
        }
    }
}

/// Define a closed string vocabulary once for its Rust enum, parser labels,
/// diagnostics, and schema consumers.
macro_rules! define_string_roster {
    (
        $(#[$enum_meta:meta])*
        $visibility:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $label:literal,
            )+
        }
    ) => {
        $(#[$enum_meta])*
        $visibility enum $name {
            $(
                $(#[$variant_meta])*
                #[serde(rename = $label)]
                $variant,
            )+
        }

        impl $name {
            /// Every label accepted by the parser, in stable declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }
        }
    };
}

define_string_roster! {
    #[doc = "Shared, public provider-kind vocabulary for signing keys.\n\nProvider-specific connection fields remain product-local so simple local config, PKCS#11, KMS, and future provider syntax can evolve independently."]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
    #[non_exhaustive]
    pub enum KeyProviderKind {
        LocalJwkEnv => "local_jwk_env",
        FileWatch => "file_watch",
        Pkcs11 => "pkcs11",
        LocalPkcs12File => "local_pkcs12_file",
        Kms => "kms",
        WorkloadIdentity => "workload_identity",
    }
}

define_string_roster! {
    #[doc = "Shared lifecycle status for a configured signing key."]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
    #[non_exhaustive]
    pub enum KeyStatus {
        Active => "active",
        PublishOnly => "publish_only",
        Disabled => "disabled",
    }
}

impl KeyStatus {
    #[must_use]
    pub const fn may_sign(self) -> bool {
        matches!(self, Self::Active)
    }

    #[must_use]
    pub const fn may_publish(self) -> bool {
        matches!(self, Self::Active | Self::PublishOnly)
    }
}

/// Shared readiness labels for public posture and apply reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KeyReadiness {
    Ready,
    Degraded,
    NotReady,
    Unknown,
}

impl KeyReadiness {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::NotReady => "not_ready",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Posture-safe readiness input for readiness-gated live apply.
///
/// This intentionally carries only shared public vocabulary. Product-specific
/// provider identifiers, local paths, slots, labels, trust domains, and
/// diagnostics stay in product-local config or private logs and must not be
/// copied into this shared snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyReadinessSnapshot {
    pub provider_kind: KeyProviderKind,
    pub status: KeyStatus,
    pub readiness: KeyReadiness,
}

impl KeyReadinessSnapshot {
    #[must_use]
    pub const fn allows_live_apply(self) -> bool {
        self.status.may_sign() && self.readiness.is_ready()
    }
}

#[derive(Clone, Deserialize)]
pub struct PrivateJwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,
}

impl fmt::Debug for PrivateJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateJwk")
            .field("kty", &self.kty)
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .field("crv", &self.crv)
            .field("d", &self.d.as_ref().map(|_| "[redacted]"))
            .field("x", &self.x)
            .field("y", &self.y)
            .field("n", &self.n.as_ref().map(|_| "[redacted]"))
            .field("e", &self.e)
            .field("p", &self.p.as_ref().map(|_| "[redacted]"))
            .field("q", &self.q.as_ref().map(|_| "[redacted]"))
            .field("dp", &self.dp.as_ref().map(|_| "[redacted]"))
            .field("dq", &self.dq.as_ref().map(|_| "[redacted]"))
            .field("qi", &self.qi.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl Serialize for PrivateJwk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.public().serialize(serializer)
    }
}

impl Drop for PrivateJwk {
    fn drop(&mut self) {
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qi.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicJwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

impl<'de> Deserialize<'de> for PublicJwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(PublicJwkVisitor)
    }
}

struct PublicJwkVisitor;

impl<'de> Visitor<'de> for PublicJwkVisitor {
    type Value = PublicJwk;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a public JWK without private key material")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut kty = None;
        let mut kid = None;
        let mut alg = None;
        let mut crv = None;
        let mut x = None;
        let mut y = None;
        let mut n = None;
        let mut e = None;

        while let Some(field) = map.next_key::<String>()? {
            match field.as_str() {
                "kty" => {
                    if kty.is_some() {
                        return Err(de::Error::duplicate_field("kty"));
                    }
                    kty = Some(map.next_value()?);
                }
                "kid" => deserialize_optional_jwk_field(&mut map, &mut kid, "kid")?,
                "alg" => deserialize_optional_jwk_field(&mut map, &mut alg, "alg")?,
                "crv" => deserialize_optional_jwk_field(&mut map, &mut crv, "crv")?,
                "x" => deserialize_optional_jwk_field(&mut map, &mut x, "x")?,
                "y" => deserialize_optional_jwk_field(&mut map, &mut y, "y")?,
                "n" => deserialize_optional_jwk_field(&mut map, &mut n, "n")?,
                "e" => deserialize_optional_jwk_field(&mut map, &mut e, "e")?,
                "k" | "d" | "p" | "q" | "dp" | "dq" | "qi" | "oth" => {
                    let _: IgnoredAny = map.next_value()?;
                    return Err(de::Error::custom("public JWK contains private material"));
                }
                _ => {
                    let _: IgnoredAny = map.next_value()?;
                }
            }
        }

        Ok(PublicJwk {
            kty: kty.ok_or_else(|| de::Error::missing_field("kty"))?,
            kid: kid.unwrap_or(None),
            alg: alg.unwrap_or(None),
            crv: crv.unwrap_or(None),
            x: x.unwrap_or(None),
            y: y.unwrap_or(None),
            n: n.unwrap_or(None),
            e: e.unwrap_or(None),
        })
    }
}

fn deserialize_optional_jwk_field<'de, A>(
    map: &mut A,
    slot: &mut Option<Option<String>>,
    field: &'static str,
) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
{
    if slot.is_some() {
        return Err(de::Error::duplicate_field(field));
    }
    *slot = Some(map.next_value()?);
    Ok(())
}

/// A key-backed signer that can produce detached signatures and publish
/// verification metadata without exposing private key material.
#[async_trait]
pub trait SigningProvider: Send + Sync {
    /// Signing algorithm advertised by this provider.
    fn algorithm(&self) -> SigningAlgorithm;
    /// Stable key identifier to publish in JWT/JWS headers.
    fn key_id(&self) -> &str;
    /// Public verification JWK for this provider.
    fn public_jwk(&self) -> PublicJwk;
    /// Current readiness of the signing backend.
    ///
    /// Local in-memory providers are ready once constructed. Providers backed by
    /// watched files, HSMs, KMS, or other external systems should override this
    /// when they can degrade after startup.
    fn readiness(&self) -> KeyReadiness {
        KeyReadiness::Ready
    }
    /// Sign the exact bytes supplied by the caller.
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError>;
}

/// Local `PrivateJwk`-backed signer for tests, demos, and mounted secret files.
#[derive(Clone)]
pub struct LocalJwkSigner {
    jwk: Arc<PrivateJwk>,
    key_id: String,
    public_jwk: PublicJwk,
    algorithm: SigningAlgorithm,
}

impl LocalJwkSigner {
    /// Build a local signer from an EdDSA (Ed25519), ES256 (P-256), ES384
    /// (P-384), RS256 (RSA), or RS384 (RSA) private JWK with a non-empty `kid`.
    pub fn new(jwk: PrivateJwk) -> Result<Self, SigningError> {
        jwk.validate_private().map_err(SigningError::InvalidKey)?;
        let algorithm = jwk.algorithm().map_err(SigningError::InvalidKey)?;
        let key_id = jwk
            .kid
            .as_deref()
            .filter(|kid| !kid.trim().is_empty())
            .ok_or(SigningError::MissingKeyId)?
            .to_string();
        let public_jwk = jwk.public();
        Ok(Self {
            jwk: Arc::new(jwk),
            key_id,
            public_jwk,
            algorithm,
        })
    }
}

impl fmt::Debug for LocalJwkSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalJwkSigner")
            .field("alg", &self.algorithm())
            .field("kid", &self.key_id)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SigningProvider for LocalJwkSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_jwk(&self) -> PublicJwk {
        self.public_jwk.clone()
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        sign(payload, self.jwk.as_ref()).map_err(SigningError::Crypto)
    }
}

#[cfg(feature = "transit")]
const MAX_TRANSIT_RESPONSE_BYTES: usize = 64 * 1024;
#[cfg(feature = "transit")]
const MAX_TRANSIT_SIGNING_INPUT_BYTES: usize = 1024 * 1024;
#[cfg(feature = "transit")]
const MAX_TRANSIT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "transit")]
const TRANSIT_SELF_TEST_MESSAGE: &[u8] = b"registry-platform-transit-signing-readiness-v1";
#[cfg(feature = "transit")]
const TRANSIT_READINESS_UNKNOWN: u8 = 0;
#[cfg(feature = "transit")]
const TRANSIT_READINESS_READY: u8 = 1;
#[cfg(feature = "transit")]
const TRANSIT_READINESS_NOT_READY: u8 = 2;

/// Validated connection and key binding for a Vault/OpenBao Transit signer.
///
/// The Transit API is reached only through a Unix socket. Authentication and
/// token renewal therefore remain the responsibility of a dedicated local
/// proxy rather than entering the application process. Configuration details
/// are deliberately redacted from `Debug` because socket, mount, and key names
/// reveal deployment topology.
#[derive(Clone)]
#[cfg(feature = "transit")]
pub struct TransitSignerConfig {
    socket_path: PathBuf,
    mount_path: String,
    key_name: String,
    key_version: u32,
    public_jwk: PublicJwk,
    request_timeout: Duration,
}

#[cfg(feature = "transit")]
impl TransitSignerConfig {
    /// Bind one immutable ES256 public identity to one explicit Transit key
    /// version. `key_version = 0` (the provider's "latest" alias) is refused so
    /// rotation cannot silently replace key bytes below an unchanged `kid`.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        mount_path: impl Into<String>,
        key_name: impl Into<String>,
        key_version: u32,
        public_jwk: PublicJwk,
        request_timeout: Duration,
    ) -> Result<Self, SigningError> {
        let socket_path = socket_path.into();
        let mount_path = mount_path.into();
        let key_name = key_name.into();
        if !socket_path.is_absolute()
            || !valid_transit_path(&mount_path)
            || !valid_transit_segment(&key_name)
            || key_version == 0
            || request_timeout.is_zero()
            || request_timeout > MAX_TRANSIT_REQUEST_TIMEOUT
            || public_jwk.algorithm().ok() != Some(SigningAlgorithm::Es256)
            || public_jwk.kid.as_deref().is_none_or(|kid| {
                kid.trim().is_empty() || kid.len() > 256 || kid.chars().any(char::is_control)
            })
        {
            return Err(transit_error("transit signer configuration is invalid"));
        }
        public_jwk
            .validate_public()
            .map_err(|_| transit_error("transit signer configuration is invalid"))?;
        Ok(Self {
            socket_path,
            mount_path,
            key_name,
            key_version,
            public_jwk,
            request_timeout,
        })
    }
}

#[cfg(feature = "transit")]
impl fmt::Debug for TransitSignerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitSignerConfig")
            .field("algorithm", &SigningAlgorithm::Es256)
            .field("key_id", &self.public_jwk.kid)
            .finish_non_exhaustive()
    }
}

/// Non-exportable ES256 signer backed by the common Vault/OpenBao Transit API.
///
/// Construction validates provider custody metadata, the pinned version, and
/// the provider's PEM public key before a sign-and-verify self-test marks the
/// signer ready. Every later signature is verified locally before release.
#[cfg(feature = "transit")]
pub struct TransitSigner {
    client: reqwest::Client,
    metadata_url: String,
    sign_url: String,
    key_version: u32,
    public_jwk: PublicJwk,
    key_id: String,
    request_timeout: Duration,
    readiness: AtomicU8,
}

#[cfg(feature = "transit")]
impl TransitSigner {
    /// Connect to Transit, validate custody and public identity metadata, and
    /// prove signing access without exporting private material.
    pub async fn initialize(config: TransitSignerConfig) -> Result<Self, SigningError> {
        let client = build_transit_client(&config)?;
        let signer = Self {
            client,
            metadata_url: format!(
                "http://localhost/v1/{}/keys/{}",
                config.mount_path, config.key_name
            ),
            sign_url: format!(
                "http://localhost/v1/{}/sign/{}/sha2-256",
                config.mount_path, config.key_name
            ),
            key_version: config.key_version,
            key_id: config
                .public_jwk
                .kid
                .as_deref()
                .expect("TransitSignerConfig validates kid")
                .to_owned(),
            public_jwk: config.public_jwk,
            request_timeout: config.request_timeout,
            readiness: AtomicU8::new(TRANSIT_READINESS_UNKNOWN),
        };
        let metadata = signer
            .request_json(reqwest::Method::GET, &signer.metadata_url, None)
            .await
            .map_err(|_| transit_error("transit signer metadata is unavailable"))?;
        signer
            .validate_metadata(&metadata)
            .map_err(|_| transit_error("transit signer metadata is invalid"))?;
        signer
            .sign(TRANSIT_SELF_TEST_MESSAGE)
            .await
            .map_err(|_| transit_error("transit signer self-test failed"))?;
        Ok(signer)
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
            .map_err(|_| transit_error("transit provider request failed"))?;
        if !response.status().is_success() {
            return Err(transit_error("transit provider request failed"));
        }
        let bytes = read_bounded_transit_response(response).await?;
        parse_json_strict(&bytes).map_err(|_| transit_error("transit provider response is invalid"))
    }

    fn validate_metadata(&self, document: &Value) -> Result<(), SigningError> {
        let data = document
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(|| transit_error("transit provider metadata is invalid"))?;
        let required_false = ["derived", "exportable", "allow_plaintext_backup"];
        if data.get("type").and_then(Value::as_str) != Some("ecdsa-p256")
            || data.get("supports_signing").and_then(Value::as_bool) != Some(true)
            || required_false
                .iter()
                .any(|field| data.get(*field).and_then(Value::as_bool) != Some(false))
        {
            return Err(transit_error("transit provider custody is invalid"));
        }

        let latest_version = data
            .get("latest_version")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| transit_error("transit provider version is invalid"))?;
        let minimum_signing_version = data
            .get("min_encryption_version")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| transit_error("transit provider version is invalid"))?;
        if self.key_version > latest_version || self.key_version < minimum_signing_version {
            return Err(transit_error("transit provider version is invalid"));
        }

        let version = self.key_version.to_string();
        let pem = data
            .get("keys")
            .and_then(Value::as_object)
            .and_then(|keys| keys.get(&version))
            .and_then(Value::as_object)
            .and_then(|key| key.get("public_key"))
            .and_then(Value::as_str)
            .ok_or_else(|| transit_error("transit provider public key is invalid"))?;
        validate_transit_public_key(pem, &self.public_jwk)
    }

    fn set_readiness(&self, readiness: KeyReadiness) {
        let encoded = match readiness {
            KeyReadiness::Ready => TRANSIT_READINESS_READY,
            KeyReadiness::NotReady | KeyReadiness::Degraded => TRANSIT_READINESS_NOT_READY,
            KeyReadiness::Unknown => TRANSIT_READINESS_UNKNOWN,
        };
        self.readiness.store(encoded, Ordering::Release);
    }
}

#[cfg(feature = "transit")]
impl fmt::Debug for TransitSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitSigner")
            .field("algorithm", &SigningAlgorithm::Es256)
            .field("key_id", &self.key_id)
            .field("readiness", &self.readiness())
            .finish_non_exhaustive()
    }
}

#[async_trait]
#[cfg(feature = "transit")]
impl SigningProvider for TransitSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Es256
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_jwk(&self) -> PublicJwk {
        self.public_jwk.clone()
    }

    fn readiness(&self) -> KeyReadiness {
        match self.readiness.load(Ordering::Acquire) {
            TRANSIT_READINESS_READY => KeyReadiness::Ready,
            TRANSIT_READINESS_NOT_READY => KeyReadiness::NotReady,
            _ => KeyReadiness::Unknown,
        }
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        if payload.len() > MAX_TRANSIT_SIGNING_INPUT_BYTES {
            return Err(transit_error("transit signing input is too large"));
        }
        let digest = Sha256::digest(payload);
        let body = serde_json::json!({
            "input": STANDARD.encode(digest),
            "key_version": self.key_version,
            "marshaling_algorithm": "jws",
            "prehashed": true,
        });
        let result = async {
            let document = self
                .request_json(reqwest::Method::POST, &self.sign_url, Some(&body))
                .await?;
            let signature = document
                .get("data")
                .and_then(|data| data.get("signature"))
                .and_then(Value::as_str)
                .ok_or_else(|| transit_error("transit provider signature is invalid"))?;
            let prefix = format!("vault:v{}:", self.key_version);
            let encoded = signature
                .strip_prefix(&prefix)
                .ok_or_else(|| transit_error("transit provider signature is invalid"))?;
            let signature = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| transit_error("transit provider signature is invalid"))?;
            if signature.len() != 64 {
                return Err(transit_error("transit provider signature is invalid"));
            }
            verify(payload, &signature, &self.public_jwk)
                .map_err(|_| transit_error("transit provider signature is invalid"))?;
            Ok(signature)
        }
        .await;
        match result {
            Ok(signature) => {
                self.set_readiness(KeyReadiness::Ready);
                Ok(signature)
            }
            Err(error) => {
                self.set_readiness(KeyReadiness::NotReady);
                Err(error)
            }
        }
    }
}

#[cfg(feature = "transit")]
fn build_transit_client(config: &TransitSignerConfig) -> Result<reqwest::Client, SigningError> {
    #[cfg(all(unix, feature = "transit"))]
    {
        reqwest::Client::builder()
            .no_proxy()
            .unix_socket(config.socket_path.clone())
            .build()
            .map_err(|_| transit_error("transit signer configuration is invalid"))
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        Err(transit_error(
            "transit signer requires Unix-domain socket support",
        ))
    }
}

#[cfg(feature = "transit")]
async fn read_bounded_transit_response(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, SigningError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_TRANSIT_RESPONSE_BYTES as u64)
    {
        return Err(transit_error("transit provider response is too large"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| transit_error("transit provider response is invalid"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_TRANSIT_RESPONSE_BYTES {
            return Err(transit_error("transit provider response is too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(feature = "transit")]
fn validate_transit_public_key(pem: &str, configured: &PublicJwk) -> Result<(), SigningError> {
    let provider = P256PublicKey::from_public_key_pem(pem)
        .map_err(|_| transit_error("transit provider public key is invalid"))?;
    let x = decode_fixed(configured.x.as_deref(), 32, "x")
        .map_err(|_| transit_error("transit provider public key is invalid"))?;
    let y = decode_fixed(configured.y.as_deref(), 32, "y")
        .map_err(|_| transit_error("transit provider public key is invalid"))?;
    let mut configured_sec1 = Vec::with_capacity(65);
    configured_sec1.push(0x04);
    configured_sec1.extend_from_slice(&x);
    configured_sec1.extend_from_slice(&y);
    if provider.to_encoded_point(false).as_bytes() != configured_sec1 {
        return Err(transit_error("transit provider public key does not match"));
    }
    Ok(())
}

#[cfg(feature = "transit")]
fn valid_transit_path(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.split('/').all(valid_transit_segment)
}

#[cfg(feature = "transit")]
fn valid_transit_segment(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(feature = "transit")]
fn transit_error(message: &'static str) -> SigningError {
    SigningError::external(message)
}

impl PrivateJwk {
    pub fn parse(json: &str) -> Result<Self, JwkError> {
        if json.len() > MAX_JWK_JSON_BYTES {
            return Err(JwkError::JsonTooLarge);
        }
        let value = parse_json_strict(json.as_bytes()).map_err(JwkError::StrictJson)?;
        reject_unsupported_private_members(&value)?;
        let jwk: Self = serde_json::from_value(value).map_err(JwkError::Json)?;
        jwk.validate_private()?;
        Ok(jwk)
    }

    #[must_use]
    pub fn public(&self) -> PublicJwk {
        PublicJwk {
            kty: self.kty.clone(),
            kid: self.kid.clone(),
            alg: self.alg.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }

    pub fn algorithm(&self) -> Result<SigningAlgorithm, JwkError> {
        algorithm_from_fields(self.alg.as_deref(), self.kty.as_str(), self.crv.as_deref())
    }

    fn validate_private(&self) -> Result<(), JwkError> {
        match self.algorithm() {
            Ok(SigningAlgorithm::EdDsa) => {
                if self.kty != "OKP" || self.crv.as_deref() != Some("Ed25519") {
                    return Err(JwkError::Invalid("EdDSA keys must be OKP/Ed25519"));
                }
                decode_fixed(self.d.as_deref(), 32, "d")?;
                decode_fixed(self.x.as_deref(), 32, "x")?;
            }
            Ok(SigningAlgorithm::Es256) => {
                if self.kty != "EC" || self.crv.as_deref() != Some("P-256") {
                    return Err(JwkError::Invalid("ES256 keys must be EC/P-256"));
                }
                let d = decode_nonempty(self.d.as_deref(), "d")?;
                if d.len() != 32 {
                    return Err(JwkError::Invalid("d"));
                }
                decode_fixed(self.x.as_deref(), 32, "x")?;
                decode_fixed(self.y.as_deref(), 32, "y")?;
            }
            Ok(SigningAlgorithm::Es384) => {
                if self.kty != "EC" || self.crv.as_deref() != Some("P-384") {
                    return Err(JwkError::Invalid("ES384 keys must be EC/P-384"));
                }
                let d = decode_nonempty(self.d.as_deref(), "d")?;
                if d.len() != 48 {
                    return Err(JwkError::Invalid("d"));
                }
                decode_fixed(self.x.as_deref(), 48, "x")?;
                decode_fixed(self.y.as_deref(), 48, "y")?;
            }
            Ok(SigningAlgorithm::Rs256) => {
                if self.kty != "RSA" {
                    return Err(JwkError::Invalid("RS256 keys must be RSA"));
                }
                validate_private_rsa_members(self)?;
            }
            Ok(SigningAlgorithm::Rs384) => {
                if self.kty != "RSA" {
                    return Err(JwkError::Invalid("RS384 keys must be RSA"));
                }
                validate_private_rsa_members(self)?;
            }
            Err(err) => return Err(err),
        }
        Ok(())
    }
}

/// RSA parameters are variable width, so only require non-empty base64url.
/// AWS-LC validates the imported PKCS#1 private key.
fn validate_private_rsa_members(jwk: &PrivateJwk) -> Result<(), JwkError> {
    decode_nonempty(jwk.n.as_deref(), "n")?;
    decode_nonempty(jwk.e.as_deref(), "e")?;
    decode_nonempty(jwk.d.as_deref(), "d")?;
    decode_nonempty(jwk.p.as_deref(), "p")?;
    decode_nonempty(jwk.q.as_deref(), "q")?;
    decode_nonempty(jwk.dp.as_deref(), "dp")?;
    decode_nonempty(jwk.dq.as_deref(), "dq")?;
    decode_nonempty(jwk.qi.as_deref(), "qi")?;
    Ok(())
}

impl PublicJwk {
    pub fn parse(json: &str) -> Result<Self, JwkError> {
        if json.len() > MAX_JWK_JSON_BYTES {
            return Err(JwkError::JsonTooLarge);
        }
        let value = parse_json_strict(json.as_bytes()).map_err(JwkError::StrictJson)?;
        reject_private_members(&value)?;
        let jwk: Self = serde_json::from_value(value).map_err(JwkError::Json)?;
        jwk.validate_public()?;
        Ok(jwk)
    }

    pub fn jkt(&self) -> Result<String, JwkError> {
        let thumbprint = match self.kty.as_str() {
            "OKP" => json_object(&[
                (
                    "crv",
                    required_thumbprint_member(self.crv.as_deref(), "crv")?,
                ),
                ("kty", "OKP"),
                ("x", required_thumbprint_member(self.x.as_deref(), "x")?),
            ]),
            "EC" => json_object(&[
                (
                    "crv",
                    required_thumbprint_member(self.crv.as_deref(), "crv")?,
                ),
                ("kty", "EC"),
                ("x", required_thumbprint_member(self.x.as_deref(), "x")?),
                ("y", required_thumbprint_member(self.y.as_deref(), "y")?),
            ]),
            "RSA" => json_object(&[
                ("e", required_thumbprint_member(self.e.as_deref(), "e")?),
                ("kty", "RSA"),
                ("n", required_thumbprint_member(self.n.as_deref(), "n")?),
            ]),
            _ => return Err(JwkError::UnsupportedAlgorithm),
        };
        let thumbprint = canonicalize_json(&thumbprint)
            .map_err(|_| JwkError::Invalid("JWK thumbprint members"))?;
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&thumbprint)))
    }

    pub fn algorithm(&self) -> Result<SigningAlgorithm, JwkError> {
        algorithm_from_fields(self.alg.as_deref(), self.kty.as_str(), self.crv.as_deref())
    }

    fn validate_public(&self) -> Result<(), JwkError> {
        match self.algorithm() {
            Ok(SigningAlgorithm::EdDsa) => {
                if self.kty != "OKP" || self.crv.as_deref() != Some("Ed25519") {
                    return Err(JwkError::Invalid("EdDSA keys must be OKP/Ed25519"));
                }
                decode_fixed(self.x.as_deref(), 32, "x")?;
            }
            Ok(SigningAlgorithm::Es256) => {
                if self.kty != "EC" || self.crv.as_deref() != Some("P-256") {
                    return Err(JwkError::Invalid("ES256 keys must be EC/P-256"));
                }
                let x = decode_coordinate(self.x.as_deref(), "x")?;
                let y = decode_coordinate(self.y.as_deref(), "y")?;
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, p256_uncompressed_point(&x, &y))
                    .parse()
                    .map_err(|_| JwkError::Invalid("ES256 public point"))?;
            }
            Ok(SigningAlgorithm::Es384) => {
                if self.kty != "EC" || self.crv.as_deref() != Some("P-384") {
                    return Err(JwkError::Invalid("ES384 keys must be EC/P-384"));
                }
                let x = decode_coordinate(self.x.as_deref(), "x")?;
                let y = decode_coordinate(self.y.as_deref(), "y")?;
                UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, p384_uncompressed_point(&x, &y))
                    .parse()
                    .map_err(|_| JwkError::Invalid("ES384 public point"))?;
            }
            Ok(SigningAlgorithm::Rs256) => {
                if self.kty != "RSA" {
                    return Err(JwkError::Invalid("RS256 keys must be RSA"));
                }
                decode_nonempty(self.n.as_deref(), "n")?;
                decode_nonempty(self.e.as_deref(), "e")?;
            }
            Ok(SigningAlgorithm::Rs384) => {
                if self.kty != "RSA" {
                    return Err(JwkError::Invalid("RS384 keys must be RSA"));
                }
                decode_nonempty(self.n.as_deref(), "n")?;
                decode_nonempty(self.e.as_deref(), "e")?;
            }
            Err(err) => return Err(err),
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwkError {
    #[error("JWK JSON exceeds the 64 KiB limit")]
    JsonTooLarge,
    #[error("invalid JWK JSON: {0}")]
    StrictJson(#[from] StrictJsonError),
    #[error("invalid JWK JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid JWK: {0}")]
    Invalid(&'static str),
    #[error("unsupported JWK algorithm")]
    UnsupportedAlgorithm,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("invalid key: {0}")]
    InvalidKey(#[from] JwkError),
    #[error("invalid base64url member: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("cryptographic operation failed: {0}")]
    Crypto(&'static str),
}

/// Errors from local and external signing providers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SigningError {
    #[error("invalid signing key: {0}")]
    InvalidKey(JwkError),
    #[error("signing key is missing kid")]
    MissingKeyId,
    #[error("signing key kid does not match public JWK")]
    KeyIdMismatch,
    #[error("cryptographic signing failed: {0}")]
    Crypto(CryptoError),
    #[error("external signer failed: {message}")]
    External { message: String },
}

impl SigningError {
    #[must_use]
    pub fn external(message: impl AsRef<str>) -> Self {
        const MAX_SAFE_CHARS: usize = 160;
        let mut chars = message
            .as_ref()
            .chars()
            .map(|ch| if ch.is_control() { ' ' } else { ch });
        let mut bounded = chars.by_ref().take(MAX_SAFE_CHARS).collect::<String>();
        if chars.next().is_some() {
            bounded.push_str("...");
        }
        Self::External { message: bounded }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidMethod {
    Web,
    Key,
    Jwk,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDid {
    pub method: DidMethod,
    pub identifier: String,
    pub fragment: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DidError {
    #[error("DID must start with did:")]
    MissingPrefix,
    #[error("DID method is not allowed")]
    MethodNotAllowed,
    #[error("DID method is unsupported")]
    UnsupportedMethod,
    #[error("DID identifier is invalid")]
    InvalidIdentifier,
    #[error("did:web host is invalid")]
    InvalidDidWebHost,
    #[error("did:web paths must not contain traversal")]
    PathTraversal,
    #[error("did:jwk payload is invalid")]
    InvalidDidJwk,
    #[error("issuer URL is invalid")]
    InvalidIssuerUrl,
    #[error("issuer URL must use HTTPS")]
    IssuerMustUseHttps,
    #[error("did:web host does not match issuer host")]
    IssuerHostMismatch,
}

pub fn validate_did(s: &str, allowed_methods: &[DidMethod]) -> Result<ValidatedDid, DidError> {
    let rest = s.strip_prefix("did:").ok_or(DidError::MissingPrefix)?;
    let (method, remainder) = rest.split_once(':').ok_or(DidError::InvalidIdentifier)?;
    let (identifier, fragment) = match remainder.split_once('#') {
        Some((identifier, fragment)) => (identifier, Some(fragment.to_string())),
        None => (remainder, None),
    };
    if identifier.is_empty() {
        return Err(DidError::InvalidIdentifier);
    }
    let method = match method {
        "web" => DidMethod::Web,
        "key" => DidMethod::Key,
        "jwk" => DidMethod::Jwk,
        _ => return Err(DidError::UnsupportedMethod),
    };
    if !allowed_methods.contains(&method) {
        return Err(DidError::MethodNotAllowed);
    }
    match method {
        DidMethod::Web => validate_did_web(s)?,
        DidMethod::Key => {
            if identifier.contains('/') || identifier.contains('?') || identifier.contains('#') {
                return Err(DidError::InvalidIdentifier);
            }
        }
        DidMethod::Jwk => {
            if identifier.contains('/') || identifier.contains('?') {
                return Err(DidError::InvalidIdentifier);
            }
            parse_did_jwk(s)?;
        }
    }
    Ok(ValidatedDid {
        method,
        identifier: identifier.to_string(),
        fragment,
    })
}

pub fn parse_did_jwk(s: &str) -> Result<PublicJwk, DidError> {
    let rest = s
        .strip_prefix("did:jwk:")
        .ok_or(DidError::UnsupportedMethod)?;
    let identifier = rest
        .split_once('#')
        .map_or(rest, |(identifier, _)| identifier);
    if identifier.is_empty() || identifier.contains('/') || identifier.contains('?') {
        return Err(DidError::InvalidIdentifier);
    }
    if identifier.len() > MAX_DID_JWK_IDENTIFIER_BYTES {
        return Err(DidError::InvalidDidJwk);
    }
    let jwk_json = URL_SAFE_NO_PAD
        .decode(identifier)
        .map_err(|_| DidError::InvalidDidJwk)?;
    if jwk_json.len() > MAX_JWK_JSON_BYTES {
        return Err(DidError::InvalidDidJwk);
    }
    let value = parse_json_strict(&jwk_json).map_err(|_| DidError::InvalidDidJwk)?;
    reject_private_members(&value).map_err(|_| DidError::InvalidDidJwk)?;
    let minimal = minimal_did_jwk_value_from_value(&value).map_err(|_| DidError::InvalidDidJwk)?;
    let jwk: PublicJwk = serde_json::from_value(minimal).map_err(|_| DidError::InvalidDidJwk)?;
    jwk.validate_public().map_err(|_| DidError::InvalidDidJwk)?;
    Ok(jwk)
}

pub fn did_jwk_from_public_jwk(jwk: &PublicJwk) -> Result<String, DidError> {
    let value = minimal_did_jwk_value(jwk).map_err(|_| DidError::InvalidDidJwk)?;
    let canonical = canonicalize_json(&value).map_err(|_| DidError::InvalidDidJwk)?;
    Ok(format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(canonical)))
}

pub fn validate_did_web(s: &str) -> Result<(), DidError> {
    let rest = s
        .strip_prefix("did:web:")
        .ok_or(DidError::UnsupportedMethod)?;
    let identifier = rest
        .split_once('#')
        .map_or(rest, |(identifier, _)| identifier);
    if identifier.is_empty() {
        return Err(DidError::InvalidIdentifier);
    }
    let mut segments = identifier.split(':');
    let host = percent_decode(segments.next().ok_or(DidError::InvalidIdentifier)?)
        .ok_or(DidError::InvalidIdentifier)?;
    validate_dns_host(&host)?;
    for segment in segments {
        let decoded = percent_decode(segment).ok_or(DidError::InvalidIdentifier)?;
        if decoded.is_empty() || decoded == "." || decoded == ".." || decoded.contains('/') {
            return Err(DidError::PathTraversal);
        }
    }
    Ok(())
}

pub fn validate_did_web_https_issuer_binding(did: &str, issuer: &str) -> Result<(), DidError> {
    validate_did_web(did)?;
    let did_host = did_web_host(did)?;
    let issuer = Url::parse(issuer).map_err(|_| DidError::InvalidIssuerUrl)?;
    if issuer.scheme() != "https" {
        return Err(DidError::IssuerMustUseHttps);
    }
    let issuer_host = issuer.host_str().ok_or(DidError::InvalidIssuerUrl)?;
    if did_host.eq_ignore_ascii_case(issuer_host) {
        Ok(())
    } else {
        Err(DidError::IssuerHostMismatch)
    }
}

#[must_use]
pub fn hmac_sha256_base64url_no_pad(key: &[u8], input: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(input);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn pairwise_subject_ref_hash(
    key: &[u8],
    aud: &str,
    issuer: &str,
    profile: &str,
    id_type: &str,
    subject_id: &str,
) -> Result<String, JcsError> {
    let input = json_string_object(&[
        ("aud", aud),
        ("issuer", issuer),
        ("profile", profile),
        ("id_type", id_type),
        ("subject_id", subject_id),
    ]);
    let canonical = canonicalize_json(&input)?;
    Ok(format!(
        "hmac-sha256:{}",
        hmac_sha256_base64url_no_pad(key, &canonical)
    ))
}

/// Sign `payload` using the private key in `jwk`.
///
/// Dispatches on the JWK algorithm: EdDSA (Ed25519), ES256 or ES384 (ECDSA
/// P-256 with SHA-256, P-384 with SHA-384), or RS256 or RS384 (RSASSA-PKCS1-v1_5
/// with SHA-256 or SHA-384). Runs synchronously on the calling thread. EdDSA is
/// measured ~15 µs/op (release, Apple M5 Max); the ECDSA and RSA algorithms are
/// slower. Callers on a Tokio
/// runtime that process many concurrent issuances should offload to
/// `tokio::task::spawn_blocking` if latency becomes a concern. Run the ignored
/// `eddsa_sign_microbench` test to re-measure on your hardware.
pub fn sign(payload: &[u8], jwk: &PrivateJwk) -> Result<Vec<u8>, CryptoError> {
    jwk.validate_private()?;
    match jwk.algorithm()? {
        SigningAlgorithm::EdDsa => sign_eddsa(payload, jwk),
        SigningAlgorithm::Es256 => sign_es256(payload, jwk),
        SigningAlgorithm::Es384 => sign_es384(payload, jwk),
        SigningAlgorithm::Rs256 => {
            sign_rsa(payload, jwk, &RSA_PKCS1_SHA256, "RS256 signing failed")
        }
        SigningAlgorithm::Rs384 => {
            sign_rsa(payload, jwk, &RSA_PKCS1_SHA384, "RS384 signing failed")
        }
    }
}

fn sign_eddsa(payload: &[u8], jwk: &PrivateJwk) -> Result<Vec<u8>, CryptoError> {
    // Decode directly into a stack-allocated Zeroizing buffer to avoid any
    // intermediate heap allocation that would not be zeroed on error paths.
    let d_str = jwk.d.as_deref().ok_or(JwkError::Invalid("d"))?;
    let mut seed = Zeroizing::new([0u8; 32]);
    let decoded_len = URL_SAFE_NO_PAD
        .decode_slice(d_str, &mut *seed)
        .map_err(|_| JwkError::Invalid("d"))?;
    if decoded_len != 32 {
        return Err(JwkError::Invalid("d length").into());
    }
    let signature = Ed25519SigningKey::from_bytes(&seed).sign(payload);
    Ok(signature.to_bytes().to_vec())
}

fn sign_es256(payload: &[u8], jwk: &PrivateJwk) -> Result<Vec<u8>, CryptoError> {
    let d = decode_nonempty(jwk.d.as_deref(), "d")?;
    if d.len() != 32 {
        return Err(JwkError::Invalid("d length").into());
    }
    let x = decode_coordinate(jwk.x.as_deref(), "x")?;
    let y = decode_coordinate(jwk.y.as_deref(), "y")?;
    // Importing the pair, rather than the scalar alone, rejects two distinct
    // unusable keys: a scalar outside 1..n-1, and a public half that belongs to
    // a different pair. The second used to sign perfectly well and produce
    // signatures no holder of the JWK's stated public half could verify.
    let key_pair = EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &d,
        &p256_uncompressed_point(&x, &y),
    )
    .map_err(|_| CryptoError::Crypto("invalid ES256 private key"))?;
    // FIXED is the raw r || s encoding JWS carries. The ASN.1 signing
    // algorithms produce a DER SEQUENCE no JWS verifier accepts.
    let signature = key_pair
        .sign(&SystemRandom::new(), payload)
        .map_err(|_| CryptoError::Crypto("ES256 signing failed"))?;
    Ok(signature.as_ref().to_vec())
}

/// Assemble the SEC 1 uncompressed point `0x04 || x || y` that aws-lc-rs reads
/// as a P-256 public half, from a JWK's fixed-width coordinates.
///
/// Taking arrays rather than slices keeps the encoding total: there is no
/// coordinate width that reaches the curve library as a malformed point.
fn p256_uncompressed_point(x: &[u8; 32], y: &[u8; 32]) -> [u8; 65] {
    let mut encoded = [0u8; 65];
    encoded[0] = 0x04;
    encoded[1..33].copy_from_slice(x);
    encoded[33..65].copy_from_slice(y);
    encoded
}

/// The P-384 counterpart of `p256_uncompressed_point`, with the same totality
/// argument. Each curve keeps its own assembler because stable Rust cannot
/// express the `2N + 1` output width a single const-generic one would need.
fn p384_uncompressed_point(x: &[u8; 48], y: &[u8; 48]) -> [u8; 97] {
    let mut encoded = [0u8; 97];
    encoded[0] = 0x04;
    encoded[1..49].copy_from_slice(x);
    encoded[49..97].copy_from_slice(y);
    encoded
}

/// Decode a JWK coordinate into the fixed width its curve requires.
fn decode_coordinate<const N: usize>(
    value: Option<&str>,
    field: &'static str,
) -> Result<[u8; N], JwkError> {
    decode_fixed(value, N, field)?
        .try_into()
        .map_err(|_| JwkError::Invalid(field))
}

fn sign_es384(payload: &[u8], jwk: &PrivateJwk) -> Result<Vec<u8>, CryptoError> {
    let d = decode_nonempty(jwk.d.as_deref(), "d")?;
    if d.len() != 48 {
        return Err(JwkError::Invalid("d length").into());
    }
    let x = decode_coordinate(jwk.x.as_deref(), "x")?;
    let y = decode_coordinate(jwk.y.as_deref(), "y")?;
    let key = EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P384_SHA384_FIXED_SIGNING,
        &d,
        &p384_uncompressed_point(&x, &y),
    )
    .map_err(|_| CryptoError::Crypto("invalid ES384 private key"))?;
    let signature = key
        .sign(&SystemRandom::new(), payload)
        .map_err(|_| CryptoError::Crypto("ES384 signing failed"))?;
    Ok(signature.as_ref().to_vec())
}

fn sign_rsa(
    payload: &[u8],
    jwk: &PrivateJwk,
    encoding: &'static RsaSignatureEncoding,
    failure: &'static str,
) -> Result<Vec<u8>, CryptoError> {
    let key = rsa_private_key(jwk)?;
    let mut signature = vec![0u8; key.public_modulus_len()];
    key.sign(encoding, &SystemRandom::new(), payload, &mut signature)
        .map_err(|_| CryptoError::Crypto(failure))?;
    Ok(signature)
}

fn rsa_private_key(jwk: &PrivateJwk) -> Result<AwsRsaKeyPair, CryptoError> {
    let der = rsa_private_key_der(jwk)?;
    AwsRsaKeyPair::from_der(der.as_bytes())
        .map_err(|_| CryptoError::Crypto("invalid RSA private key components"))
}

fn rsa_private_key_der(jwk: &PrivateJwk) -> Result<SecretDocument, CryptoError> {
    let n = decode_nonempty(jwk.n.as_deref(), "n")?;
    let e = decode_nonempty(jwk.e.as_deref(), "e")?;
    let d = decode_nonempty(jwk.d.as_deref(), "d")?;
    let p = decode_nonempty(jwk.p.as_deref(), "p")?;
    let q = decode_nonempty(jwk.q.as_deref(), "q")?;
    let dp = decode_nonempty(jwk.dp.as_deref(), "dp")?;
    let dq = decode_nonempty(jwk.dq.as_deref(), "dq")?;
    let qi = decode_nonempty(jwk.qi.as_deref(), "qi")?;

    let key = Pkcs1RsaPrivateKey {
        modulus: rsa_uint(&n, "n")?,
        public_exponent: rsa_uint(&e, "e")?,
        private_exponent: rsa_uint(&d, "d")?,
        prime1: rsa_uint(&p, "p")?,
        prime2: rsa_uint(&q, "q")?,
        exponent1: rsa_uint(&dp, "dp")?,
        exponent2: rsa_uint(&dq, "dq")?,
        coefficient: rsa_uint(&qi, "qi")?,
        other_prime_infos: None,
    };
    SecretDocument::encode_msg(&key)
        .map_err(|_| CryptoError::Crypto("invalid RSA private key components"))
}

fn rsa_uint<'a>(bytes: &'a [u8], field: &'static str) -> Result<UintRef<'a>, CryptoError> {
    UintRef::new(bytes).map_err(|_| JwkError::Invalid(field).into())
}

/// Verify `signature` over `payload` using the public key in `jwk`.
///
/// Dispatches on the JWK algorithm: EdDSA (Ed25519), ES256 or ES384 (ECDSA
/// P-256 with SHA-256, P-384 with SHA-384), or RS256 or RS384 (RSASSA-PKCS1-v1_5
/// with SHA-256 or SHA-384). Runs synchronously on the calling thread. EdDSA is
/// measured ~22 µs/op (release, Apple M5 Max). Run
/// the ignored `eddsa_verify_microbench` test to re-measure on your hardware.
pub fn verify(payload: &[u8], signature: &[u8], jwk: &PublicJwk) -> Result<(), CryptoError> {
    jwk.validate_public()?;
    match jwk.algorithm()? {
        SigningAlgorithm::EdDsa => verify_eddsa(payload, signature, jwk),
        SigningAlgorithm::Es256 => verify_es256(payload, signature, jwk),
        SigningAlgorithm::Es384 => verify_es384(payload, signature, jwk),
        SigningAlgorithm::Rs256 => verify_rsa(payload, signature, jwk, &RSA_PKCS1_2048_8192_SHA256),
        SigningAlgorithm::Rs384 => verify_rsa(payload, signature, jwk, &RSA_PKCS1_2048_8192_SHA384),
    }
}

fn verify_eddsa(payload: &[u8], signature: &[u8], jwk: &PublicJwk) -> Result<(), CryptoError> {
    let x = decode_fixed(jwk.x.as_deref(), 32, "x")?;
    let x: [u8; 32] = x.try_into().map_err(|_| JwkError::Invalid("x length"))?;
    let verifying_key =
        Ed25519VerifyingKey::from_bytes(&x).map_err(|_| CryptoError::InvalidSignature)?;
    let signature =
        Ed25519Signature::try_from(signature).map_err(|_| CryptoError::InvalidSignature)?;
    verifying_key
        .verify_strict(payload, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

fn verify_es256(payload: &[u8], signature: &[u8], jwk: &PublicJwk) -> Result<(), CryptoError> {
    let verifying_key = p256_verifying_key(jwk)?;
    let signature =
        P256Signature::from_slice(signature).map_err(|_| CryptoError::InvalidSignature)?;
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

fn p256_verifying_key(jwk: &PublicJwk) -> Result<P256VerifyingKey, CryptoError> {
    let x = decode_fixed(jwk.x.as_deref(), 32, "x")?;
    let y = decode_fixed(jwk.y.as_deref(), 32, "y")?;
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..65].copy_from_slice(&y);
    P256VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidSignature)
}

fn verify_es384(payload: &[u8], signature: &[u8], jwk: &PublicJwk) -> Result<(), CryptoError> {
    let x = decode_coordinate(jwk.x.as_deref(), "x")?;
    let y = decode_coordinate(jwk.y.as_deref(), "y")?;
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, p384_uncompressed_point(&x, &y))
        .verify(payload, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

fn verify_rsa(
    payload: &[u8],
    signature: &[u8],
    jwk: &PublicJwk,
    parameters: &RsaParameters,
) -> Result<(), CryptoError> {
    let n = decode_nonempty(jwk.n.as_deref(), "n")?;
    let e = decode_nonempty(jwk.e.as_deref(), "e")?;
    let key = AwsRsaPublicKeyComponents {
        n: n.as_slice(),
        e: e.as_slice(),
    };
    key.verify(parameters, payload, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

fn algorithm_from_fields(
    alg: Option<&str>,
    kty: &str,
    crv: Option<&str>,
) -> Result<SigningAlgorithm, JwkError> {
    match alg {
        Some("EdDSA") => Ok(SigningAlgorithm::EdDsa),
        Some("ES256") => Ok(SigningAlgorithm::Es256),
        Some("RS256") => Ok(SigningAlgorithm::Rs256),
        Some("ES384") => Ok(SigningAlgorithm::Es384),
        Some("RS384") => Ok(SigningAlgorithm::Rs384),
        Some(_) => Err(JwkError::UnsupportedAlgorithm),
        None if kty == "OKP" && crv == Some("Ed25519") => Ok(SigningAlgorithm::EdDsa),
        // RSA keys must carry an explicit RSA alg; never inferred from kty.
        None => Err(JwkError::UnsupportedAlgorithm),
    }
}

fn reject_private_members(value: &Value) -> Result<(), JwkError> {
    const PRIVATE_MEMBERS: [&str; 8] = ["k", "d", "p", "q", "dp", "dq", "qi", "oth"];
    if PRIVATE_MEMBERS
        .iter()
        .any(|member| value.get(member).is_some())
    {
        return Err(JwkError::Invalid("public JWK contains private material"));
    }
    Ok(())
}

fn reject_unsupported_private_members(value: &Value) -> Result<(), JwkError> {
    if ["k", "oth"]
        .iter()
        .any(|member| value.get(member).is_some())
    {
        return Err(JwkError::Invalid("unsupported private JWK material"));
    }
    Ok(())
}

fn minimal_did_jwk_value(jwk: &PublicJwk) -> Result<Value, JwkError> {
    jwk.validate_public()?;
    if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
        return Err(JwkError::UnsupportedAlgorithm);
    }
    Ok(json_object(&[
        ("crv", "Ed25519"),
        ("kty", "OKP"),
        ("x", required_thumbprint_member(jwk.x.as_deref(), "x")?),
    ]))
}

fn minimal_did_jwk_value_from_value(value: &Value) -> Result<Value, JwkError> {
    const DID_JWK_MEMBERS: [&str; 5] = ["kty", "crv", "x", "kid", "alg"];
    let Some(object) = value.as_object() else {
        return Err(JwkError::Invalid("JWK must be an object"));
    };
    if object
        .keys()
        .any(|member| !DID_JWK_MEMBERS.contains(&member.as_str()))
    {
        return Err(JwkError::Invalid("did:jwk contains unsupported members"));
    }
    let jwk = PublicJwk::deserialize(value).map_err(JwkError::Json)?;
    minimal_did_jwk_value(&jwk)
}

fn required_thumbprint_member<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, JwkError> {
    let value = value.ok_or(JwkError::Invalid(field))?;
    if value.is_empty() {
        return Err(JwkError::Invalid(field));
    }
    Ok(value)
}

fn json_object(entries: &[(&str, &str)]) -> Value {
    json_string_object(entries)
}

fn json_string_object(entries: &[(&str, &str)]) -> Value {
    let mut object = Map::new();
    for (key, value) in entries {
        object.insert((*key).to_string(), Value::String((*value).to_string()));
    }
    Value::Object(object)
}

fn decode_fixed(
    value: Option<&str>,
    expected_len: usize,
    field: &'static str,
) -> Result<Vec<u8>, JwkError> {
    let value = value.ok_or(JwkError::Invalid(field))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| JwkError::Invalid(field))?;
    if decoded.len() != expected_len {
        return Err(JwkError::Invalid(field));
    }
    Ok(decoded)
}

fn decode_nonempty(
    value: Option<&str>,
    field: &'static str,
) -> Result<Zeroizing<Vec<u8>>, JwkError> {
    let value = value.ok_or(JwkError::Invalid(field))?;
    // The decoded buffer can hold private RSA components (d, p, q), so wrap it
    // in Zeroizing to clear the bytes when the buffer drops, including on the
    // validation paths that decode purely to check the field and discard it.
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| JwkError::Invalid(field))?,
    );
    if decoded.is_empty() {
        return Err(JwkError::Invalid(field));
    }
    Ok(decoded)
}

fn validate_dns_host(host: &str) -> Result<(), DidError> {
    if host.parse::<IpAddr>().is_ok() {
        return Err(DidError::InvalidDidWebHost);
    }
    if Host::parse(host).is_err() {
        return Err(DidError::InvalidDidWebHost);
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost"
        || lower.ends_with(".localhost")
        || lower == "metadata.google.internal"
        || lower.contains("169.254.169.254")
    {
        return Err(DidError::InvalidDidWebHost);
    }
    if lower
        .split('.')
        .any(|label| label.is_empty() || label == "." || label == "..")
    {
        return Err(DidError::InvalidDidWebHost);
    }
    Ok(())
}

fn did_web_host(s: &str) -> Result<String, DidError> {
    let rest = s
        .strip_prefix("did:web:")
        .ok_or(DidError::UnsupportedMethod)?;
    let identifier = rest
        .split_once('#')
        .map_or(rest, |(identifier, _)| identifier);
    let host = identifier
        .split(':')
        .next()
        .ok_or(DidError::InvalidIdentifier)?;
    percent_decode(host).ok_or(DidError::InvalidIdentifier)
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = *bytes.get(index + 1)?;
            let lo = *bytes.get(index + 2)?;
            out.push((hex_value(hi)? << 4) | hex_value(lo)?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The Transit tests derive a provider's public half from a scalar to build
    // the PEM a real provider would publish. Signing itself no longer reaches
    // for RustCrypto, so this import is test scaffolding, not a signing path.
    #[cfg(all(unix, feature = "transit"))]
    use p256::ecdsa::SigningKey as P256SigningKey;
    #[cfg(all(unix, feature = "transit"))]
    use p256::pkcs8::{EncodePublicKey as _, LineEnding};
    use serde_json::json;
    #[cfg(all(unix, feature = "transit"))]
    use tempfile::TempDir;
    #[cfg(all(unix, feature = "transit"))]
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    #[cfg(all(unix, feature = "transit"))]
    use tokio::net::UnixListener;
    #[cfg(all(unix, feature = "transit"))]
    use tokio::task::JoinHandle;

    const RAW_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;
    const P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"did:web:issuer.test#p256-key-1"}"#;
    /// A second, unrelated P-256 pair. Its private scalar is 1, so `x` and `y`
    /// are the curve's base point: a valid public half that belongs to no other
    /// key in these tests.
    const SECOND_P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","alg":"ES256","kid":"did:web:issuer.test#p256-key-2"}"#;

    const ES256_FIXED_VECTOR_PAYLOAD: &[u8] = b"registry-platform-crypto es256 migration vector";
    /// A signature over `ES256_FIXED_VECTOR_PAYLOAD` with `P256_JWK`, produced
    /// by the RustCrypto `p256` signer this crate used before ES256 signing
    /// moved to aws-lc-rs.
    ///
    /// Frozen so the backend move cannot quietly narrow what this crate
    /// accepts. Every Evidence response signed before the move carries a
    /// signature of exactly this shape, and must still verify after it.
    const ES256_PRE_MIGRATION_SIGNATURE: &str =
        "Rle6NzhA6z80JzmFr-GdJqUws2TlPoxXAtod7KVT9hPw6xfOdBHaD56f6NKxATy3b7bo8pL-Fq2mFiMyzeqy9w";
    const P384_JWK: &str = r#"{"kty":"EC","crv":"P-384","d":"Cp2oq8BnIF6oQ2KWV-1yiR7Mf0rFOuDZ5nvS9E_9HGEODI76izZiDEFQ5kfSwCAg","x":"TH-XDvwYtzdc43QDOiBjfdQZTCx1k9Rz5ELDu_2NS8JWcCv8HlfK0T9rYijDIcAY","y":"eLx0gh3VmCC2DeubmC0CdDgno7aEBYEkz5Legyg-2GoLlFohSIop3zKCGSjhg7Ta","alg":"ES384","kid":"did:web:issuer.test#p384-key-1"}"#;

    const ES384_OPENSSL_VECTOR_PAYLOAD: &[u8] =
        b"registry-platform-crypto openssl 3.6.2 es384 known-answer vector";
    /// The public half of a P-384 pair OpenSSL 3.6.2 generated, `x` and `y`
    /// taken from the uncompressed point OpenSSL prints for that key.
    const ES384_OPENSSL_PUBLIC_JWK: &str = r#"{"kty":"EC","crv":"P-384","x":"5DdfCWW37biY67BYT5RfqwwonZP6KVlTkmGD5REYpY3R1U0cDRCcerer26H1T3zc","y":"fIP0mOBgT2Py6DZelcG6BFvJROt8g43lX4g8XIeVujRy4H1ghKeUJh1WWk0XPBO1","alg":"ES384","kid":"openssl-es384-vector"}"#;
    /// OpenSSL 3.6.2's ES384 signature over `ES384_OPENSSL_VECTOR_PAYLOAD` with
    /// the pair above, rewritten from the ASN.1 DER SEQUENCE OpenSSL emits into
    /// the raw `r || s` JWS carries: each of `r` and `s` left-padded to the
    /// curve's 48-byte width.
    const ES384_OPENSSL_SIGNATURE: &str = "MQ4axJZgmlYpKgUgXCxo1-9FHqhClByVu8PX9iK0BBuFD5RISplywLqpzUgd8o4uNXI8dYRxDbKaOMqKBCw0ofjUehrD7MUl1H8IGKi3km2XaTx62UrO8OH9A0lT8nmK";

    #[cfg(all(unix, feature = "transit"))]
    struct MockTransitReply {
        method: &'static str,
        path: &'static str,
        body: Option<Value>,
        status: u16,
        response: Vec<u8>,
        delay: Duration,
    }

    #[cfg(all(unix, feature = "transit"))]
    fn spawn_transit_mock(replies: Vec<MockTransitReply>) -> (TempDir, PathBuf, JoinHandle<()>) {
        let directory = tempfile::tempdir().expect("temporary Transit directory");
        let socket_path = directory.path().join("transit.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind mock Transit socket");
        let task = tokio::spawn(async move {
            for reply in replies {
                let (mut stream, _) = listener.accept().await.expect("accept Transit request");
                let mut request = Vec::new();
                let header_end = loop {
                    let mut chunk = [0_u8; 4096];
                    let read = stream.read(&mut chunk).await.expect("read Transit request");
                    assert_ne!(read, 0, "Transit request ended before its headers");
                    request.extend_from_slice(&chunk[..read]);
                    assert!(request.len() <= 128 * 1024, "mock request stayed bounded");
                    if let Some(position) =
                        request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                };
                let headers = std::str::from_utf8(&request[..header_end])
                    .expect("Transit request headers are UTF-8");
                let mut lines = headers.lines();
                let request_line = lines.next().expect("request line");
                let mut request_parts = request_line.split_whitespace();
                assert_eq!(request_parts.next(), Some(reply.method));
                assert_eq!(request_parts.next(), Some(reply.path));
                let lower_headers = headers.to_ascii_lowercase();
                assert!(
                    lower_headers.contains("x-vault-request: true"),
                    "Transit request marks the trusted proxy hop"
                );
                let content_length = lines
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse::<usize>().expect("content length"))
                    .unwrap_or(0);
                while request.len() < header_end + content_length {
                    let mut chunk = [0_u8; 4096];
                    let read = stream
                        .read(&mut chunk)
                        .await
                        .expect("read Transit request body");
                    assert_ne!(read, 0, "Transit request body ended early");
                    request.extend_from_slice(&chunk[..read]);
                }
                let actual_body = &request[header_end..header_end + content_length];
                match reply.body {
                    Some(expected) => {
                        let actual: Value =
                            serde_json::from_slice(actual_body).expect("Transit request JSON");
                        assert_eq!(actual, expected);
                    }
                    None => assert!(actual_body.is_empty()),
                }

                if !reply.delay.is_zero() {
                    tokio::time::sleep(reply.delay).await;
                }
                let reason = if reply.status == 200 { "OK" } else { "ERROR" };
                let response_headers = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.status,
                    reason,
                    reply.response.len()
                );
                let _ = stream.write_all(response_headers.as_bytes()).await;
                let _ = stream.write_all(&reply.response).await;
            }
        });
        (directory, socket_path, task)
    }

    #[cfg(all(unix, feature = "transit"))]
    fn p256_public_pem(private: &PrivateJwk) -> String {
        let scalar = decode_fixed(private.d.as_deref(), 32, "d").expect("P-256 scalar");
        let signing = P256SigningKey::from_slice(&scalar).expect("P-256 signing key");
        let encoded = signing.verifying_key().to_encoded_point(false);
        let public = P256PublicKey::from_sec1_bytes(encoded.as_bytes()).expect("P-256 public key");
        public
            .to_public_key_pem(LineEnding::LF)
            .expect("P-256 public PEM")
    }

    #[cfg(all(unix, feature = "transit"))]
    fn transit_metadata(public_key: &str) -> Value {
        json!({
            "data": {
                "type": "ecdsa-p256",
                "derived": false,
                "exportable": false,
                "allow_plaintext_backup": false,
                "imported": true,
                "deletion_allowed": true,
                "supports_signing": true,
                "latest_version": 9,
                "min_encryption_version": 2,
                "keys": {
                    "7": {
                        "creation_time": "2026-08-06T00:00:00Z",
                        "public_key": public_key,
                    }
                }
            }
        })
    }

    // Mirrors the documented Vault Transit read-key response, extended with
    // the versioned P-256 public-key object returned for an asymmetric key.
    #[cfg(all(unix, feature = "transit"))]
    fn vault_transit_metadata_response_fixture(public_key: &str) -> Value {
        json!({
            "data": {
                "type": "ecdsa-p256",
                "deletion_allowed": false,
                "derived": false,
                "exportable": false,
                "allow_plaintext_backup": false,
                "keys": {
                    "7": {
                        "creation_time": "2026-08-06T00:00:00Z",
                        "public_key": public_key,
                    }
                },
                "latest_version": 9,
                "min_decryption_version": 1,
                "min_encryption_version": 2,
                "name": "vault-evidence-key",
                "supports_encryption": false,
                "supports_decryption": false,
                "supports_derivation": false,
                "supports_signing": true,
                "imported": false,
            }
        })
    }

    // OpenBao documents the same Transit read-key wire schema. Keep a
    // separate fixture so a future provider divergence cannot be hidden by a
    // generic compatibility test.
    #[cfg(all(unix, feature = "transit"))]
    fn openbao_transit_metadata_response_fixture(public_key: &str) -> Value {
        json!({
            "data": {
                "type": "ecdsa-p256",
                "deletion_allowed": true,
                "derived": false,
                "exportable": false,
                "allow_plaintext_backup": false,
                "keys": {
                    "7": {
                        "creation_time": "2026-08-06T00:00:00Z",
                        "public_key": public_key,
                    }
                },
                "latest_version": 9,
                "min_decryption_version": 1,
                "min_encryption_version": 2,
                "name": "openbao-evidence-key",
                "supports_encryption": false,
                "supports_decryption": false,
                "supports_derivation": false,
                "supports_signing": true,
                "imported": true,
            }
        })
    }

    #[cfg(all(unix, feature = "transit"))]
    fn transit_signature(private: &PrivateJwk, payload: &[u8], version: u32) -> Value {
        let signature = sign(payload, private).expect("mock Transit signature");
        json!({
            "data": {
                "signature": format!("vault:v{version}:{}", URL_SAFE_NO_PAD.encode(signature))
            }
        })
    }

    #[cfg(all(unix, feature = "transit"))]
    fn vault_transit_sign_response_fixture(
        private: &PrivateJwk,
        payload: &[u8],
        version: u32,
    ) -> Value {
        transit_signature(private, payload, version)
    }

    #[cfg(all(unix, feature = "transit"))]
    fn openbao_transit_sign_response_fixture(
        private: &PrivateJwk,
        payload: &[u8],
        version: u32,
    ) -> Value {
        transit_signature(private, payload, version)
    }

    #[cfg(all(unix, feature = "transit"))]
    fn transit_request(payload: &[u8], version: u32) -> Value {
        let digest = Sha256::digest(payload);
        json!({
            "input": STANDARD.encode(digest),
            "key_version": version,
            "marshaling_algorithm": "jws",
            "prehashed": true,
        })
    }

    #[cfg(all(unix, feature = "transit"))]
    fn transit_reply(
        method: &'static str,
        path: &'static str,
        body: Option<Value>,
        response: Value,
    ) -> MockTransitReply {
        MockTransitReply {
            method,
            path,
            body,
            status: 200,
            response: serde_json::to_vec(&response).expect("mock response JSON"),
            delay: Duration::ZERO,
        }
    }

    // Test-only 2048-bit RSA private JWK (kty=RSA, alg=RS256). Generated once
    // with openssl and converted to JWK; used only by RS256 tests. Not a
    // production key.
    const RSA_JWK: &str = r#"{"kty":"RSA","kid":"registry-notary-rs256-test","alg":"RS256","n":"yIgEn3IXWI3CRyUY0gvZ-kJ55EC36MRFvj-ICsitN1-50phRS4CKMBRwbHwjgeTkbMDndOCmVfIbyKhJjOMIPxAzIHeMn9oWj5i-s8nlSgjHZpvCTnRbwZhbq6mEVoHJliX36IfV_iUopcwSL5lPd2wZmJ-msUmZFs6CTRExu0JGUJScOwFO5dqxBwiKyh7yGEPXI3u4tc3_47SZYxyde7fb-o3wl2RBJ28upa2jVRP9r-WjOGjE6tbZ35HnVUY4ECdYWzsiotg_XA9QVWa-pAKXV2Flr-gocCQ9E2qrSYjEbNXuFjPtMnuL6AHi0o5PiwT1dllcl925hpKd7Xt60w","e":"AQAB","d":"ATDtMhpe_z1-GTUV7NLO3V_Z0kb8W1YXkC7JbJTAdcE-FdKJrtu84Q87WpxG0tPcutFPLqW12QAQp2fbmxhZ6VrfVYneeOlEjO14ukqM_g35Z-eRDmYhwoFYrEWGqlH9XrZysHhKFZyKHW_G0lJV-Ks8Na_RFNNIXeVedVMQiytAFXibTHvdAdIrBGtt0M4tlQOCeRwnuoAQU-a5VB7rKGpxnJtUA7F_jjeX6jQPnUhkOXs20pPRey-i-jxwBbsF4XijHgTnGwAo5uOoY9b0kOmOb3Hs5TVqZCb3a4JoYAqZBbWrkKxccJTGMqLHCe0MBgQzKqP5KyrHRgQdzlmTnQ","p":"5xhkHe5lD7tUYJAFffHiRpy4unHfKDvTEASu8RBgWvHP2Hu5XLQU5n6DvI47LsW42swTcT6Ce1pWB2LK3SjKcw9FPEEGg8m5-tmfixaRq4DBaK0hj17763HmnYR0eQC0n_5y-My8WSC1y80T-AhKHJ_3xTtLXQd5Z9bf9MEiKS8","q":"3iRoiwbnn8oRJMjZUZhqKB-GVa7AJV0SUqXiUsBAJnqtbhuIESbkJKpt5eULeUQgdNkoG65KD-jXFUipWX1zlentc1FliCaB46jntqtxUsui8LNwKw_eb3nujQO7H1He4NJ5pfaLfRcmBOLwB-u2Z1cxrRDWhIgiHtGaAdQ7F50","dp":"j4h9vn1wNbozaRpq3tPap-L1dY_-e93UdPGDuuRiBHqGjr4h3itXg-X2aqmopp9V9kekl8SshHMSVdoNiBmqzJYieY8lvbsQkXaTem8VIQGCn0JRQtxK-eyvwQwgz3sZtPn0bQW0wmLnp2KD0Z1McsUEvnLalzhqNo2mYj2Guy8","dq":"0T6ySuLCIz2PUHrwWW-b7xdizirBS3CT5c3jldcJljVQT7sXPDDKDc-LnVVWrW-Csw4qPYi6sqm8j4vWGTmWOswSouE1Jj4_c1aSjPqI0FiIrvoW2jkkaRUNoz60cBgKPPOFKtNFKRs48LljJ9LcChOT81U8-7HPkgAVdUuYLfE","qi":"PnMeCE0dvWDLp2Dn1wsxtl-a0qjpkT9cp8EkvHYjCvVqqWqrVv84CoEo-1wA9j_VDvCG6T4n0UO9K0jfBf5yvPnahSQCLJk2nw-2uZ9YzBZKwkm21wU6hTknPst5Vk5ZbYJmzqXsCqEB5T2Bn5vqeXMe3SOB5hD2CbTFFfp3TC4"}"#;

    // Test-only 1024-bit RSA private JWK plus a valid RS256 signature over
    // `registry-notary-rs256-1024`. These pin the AWS-LC 2048-bit RSA floor.
    const RSA_1024_JWK: &str = r#"{"kty":"RSA","kid":"registry-notary-rs256-1024-test","alg":"RS256","n":"0XamHpbNC-FqjNCuvjTv3JlceEpQlZtsULPcCTy0CYnGxMNHNYUdcUuVXSFtIQCpHPWUwLL-GWu5PmF_svocDHHsbnlbPj3Eg9dVN2m1g-du7jK1IA3eeTmfWZAkZC9R_ITsULIr7QjrMrUm2GgejMLqnaeZpVxmCD6X6ER02Ik","e":"AQAB","d":"yOuWzSC57vt6yTgjZjBBJMm2-WvPgLJlY8Qi_HlN-Rg_od3vIFdftp1Z2MuHcnC_xxeKaI1JT_kU59F-PJ_M5iWqT5f4fXLgEcBMkBjXTgK-uK3hwHQUKz7F20p3_hJDZoG9v1bBxLhBtk1NPx2O1GggRsrAVpw1yy6ZwcwdRkE","p":"-Vee6DQ7Sam8Gr1BFda8bkY2RufiBmJ6rQvZiOD3kOU8Lm9lQYQ0l4_w2n3KBblsQ6qamCfw2_WLDxgBiyn94w","q":"1w5vxxGu66T1WEJo-yl8Xz109DrG9upv-YNuPUPHy9U6B4A8_2iaK1ony6jwwmEDmroepEw8CpX9M0IySA3bow","dp":"D3seNaKQj8lHEY3wjY-QkXQwiIR7JxRUM4xJzFLTbB6fdu6ZpdC0hzh7psUqluJlU2ozQQEx1iZPpPdDmUVZKw","dq":"TCmWuJ-wnU_cfBd46op0u54eT2iJkmTQp0M-xX-9wJiRZpqp_6JiBzx0n5IDQjPtfNyxgWpmUTFxbLfi6tXNlQ","qi":"qA3t0sbVQvSRcUYOZmh9re_Ln6B5qxfqUcgRG7naqe1HL_7pGpE9CaeVZ_koLmXSRrYZ8Y5m14vJjQd7aGta8w"}"#;
    const RSA_1024_SIGNATURE: &str = "AHSzPijESokHRJWCXV0Vc_n0Faee3y4fU1z4-f8qT5BbvHX8sM9BknCVTfg4AWCB6szaVJV5J3oeLlTM8qGIrLj1qMewYjhxbNymNoDkzXTiYDt_NJw28LooZiXAZYmy8HK7EJqwnbvyS4-0j4KpiXl1MkNHYIe_l3JuvG-af24";

    const RS384_OPENSSL_VECTOR_PAYLOAD: &[u8] =
        b"registry-platform-crypto openssl 3.6.2 rs384 known-answer vector";
    /// A 2048-bit RSA private JWK carrying the CRT components OpenSSL 3.6.2
    /// prints for a key it generated. Test-only material, not a production key.
    const RS384_OPENSSL_PRIVATE_JWK: &str = r#"{"kty":"RSA","kid":"openssl-rs384-vector","alg":"RS384","n":"odXWNdjRAm54dJ0hOG_nKhW7oHn1sDvVRZYohv9yws51rUiMB_QS1n2J2MjOaCfM3Htp2jQHW4fZNGMOrjE1CuJuFInTKAAHrJtFRmQb54rY2kc7meLrN7PS4sxkjoh5vbcl3B9ZJ3dpqWw8fa7tg3priRhmj9eb67f7C0fOl2zRRez1kmq7bxm29jvEE4ZK3rYhm5ZvfYKhnK1bQFdm5X0FjbxUcZtd1BREUdmqUQebEPQwlFvRv0Qupq5rrn3ZgDwn9Dbji40WXtbfISNuEocTIGOO7hfd-D42wCZlWrn8CJGuNd2bwXC-fEZBIfSk5pIB_b_cfubWOyvxnyz6bQ","e":"AQAB","d":"PScdIU7TN_x_hu1DOtzKOLRqqGq9hMEvR3LE0LJhbqxuejLSO0UnAyb_-kty95emiWAXMS185EDyuiF-UCNm_DxwxVEJWfGc9MPdiwpUIwvsApttMaq2IF_SngIHM3btrdsxsrqjyU6NvkgYmZOKy6ZsUStHwi4CjLGCaxJQxhXt9Wbqek5DDCS8G8Bzjy-oUBsInTpuxPWGMOWtpcu6w-dDj5wCALNzKJmAc7SVhUTNXY1V-kwZSkq_mjCZvKPH_6m2Xqzzr-UINnoq5hOI8Jp43MTjdHnS6tFegFqAiQe4SRJL83cTjVzSXAINNXpdNrexSwB_qCeY63Sx2F2Vjw","p":"1vz7HVe4XJNvFjxaq4KAebHjaFUE2uaKpYGWCRW2_FoanDnW7WmqRDpU_mb1elO3Su4kLYMzFCHiSOQie_8cgGoEyLE2Eg1MGnRyoW2pwt77RP5fchc4gkQEw6JguT-0IiPlip_NWi60p0n8zXmd_y_2SE0d4yyMYInOOoydP0s","q":"wLUdx51lQ_tbpc1ILAJ6ds2SKh715PVzBMo_vVmR5uGOduw00XZm_87tF8-JzN2sP0MARY-S-3BHsCvvIRxbUeMrC2FXDzAwWZ-zOEl0r5vbOPOhMSSzIX94RZPtqI3o6zHsPFYZxtU8g8WMiLGe5K1srLbs1zo5KYq_5s9VQic","dp":"k0R2S9JUEu5XkTbEsWnS0gn-CfD7Q2vbG6aZ_R0n3NNoGQ4x4S2ZmeUPZblnfGUuUKCynY6bBbZ0SJQl3ySRBJIbNtLVhCYhtJmCEHyLZlbSbp-FCCVJ60nmrZBki2FM5noKehwfUiBeVZ4EE0i05yKWpU5WI9DXVCXx4_-Ak-M","dq":"qn1SPHEuz0dJXNXSHUWQDR1wTB2aFJdmy_0XCTF-WJKDVQlC7XHgTD9JGYC-fGY95rYjPmd4dUVv1xf3dwa8cCUXxvi2ajSLAi-9AnZSaq7r82Xv3SeH54H76Sqn3zC1uacwRm0yXuv2nuoenCzw04XvGJq5zOyw9-TORKh32I8","qi":"e4kQt1SOxFswplA_tfw9Xz4qN7zmM8vdcAN3lyeDBvTRaKtumH6mtDSPmdu7_3XbvK5A8ARxlOiInTtFOF_NnMEsiQXtn3GnA9z3euJmY7zHT_bKYveQIk6tvHaOaXvtghWKBDDm8lPUNLjCj2uQISbE0Ai5To7fu7-AVV6n4cw"}"#;
    /// OpenSSL 3.6.2's RS384 signature over `RS384_OPENSSL_VECTOR_PAYLOAD` with
    /// the key above.
    const RS384_OPENSSL_SIGNATURE: &str = "TyTgylxchYn-SuG-mYzIpsu7RUlans7MbxyAboqGbyVmejbLd8C_bYt9p13wotq_pgs0JnslQ6RmZTh0-rFaZ4E_ZFf1ZxwQbB7Hud2WMCTs0fSh33k-XaauTXxZfSXrecojQrxrB_U1XBQpvL9olz0fygRcBal59ZuGGkTLPMD7RNUwDkMpZ16fs2aNIjiubvT4zG9HS3_kshgi5ATmzjiLQYrS5uLsyCZI7Fqfcar5cH6yJTZScdJgXEiKGtM1pEKZ6leSAkW7OCfYvHPPHXONo2nHxM15I1BnEh5aTfeBHYLm8HBQrXm5NaOmYXX7PYqzu7AvdFs2zxLfY5F6SQ";

    #[test]
    fn private_jwk_parse_debug_redacts_and_public_strips_private_material() {
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let debug = format!("{private:?}");

        assert!(debug.contains("PrivateJwk"));
        assert!(!debug.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
        assert!(debug.contains("[redacted]"));

        let projected = private.public();
        let encoded = serde_json::to_string(&projected).expect("public JWK serializes");
        let public = PublicJwk::parse(&encoded).expect("P-256 public JWK parses");
        let public_json = serde_json::to_value(&public).expect("public jwk serializes");
        assert_eq!(
            public_json.get("x").and_then(Value::as_str),
            private.x.as_deref()
        );
        assert!(public_json.get("d").is_none());
    }

    #[test]
    fn jwk_parsers_reject_duplicate_members_before_key_interpretation() {
        let duplicate = r#"{"kty":"OKP","\u006bty":"EC","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

        assert!(matches!(
            PrivateJwk::parse(duplicate),
            Err(JwkError::StrictJson(_))
        ));
        assert!(matches!(
            PublicJwk::parse(duplicate),
            Err(JwkError::StrictJson(_))
        ));
    }

    #[test]
    fn private_jwk_serializes_as_public_projection() {
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let serialized = serde_json::to_value(&private).expect("private jwk serializes safely");

        assert_eq!(
            serialized.get("x").and_then(Value::as_str),
            private.x.as_deref()
        );
        assert!(serialized.get("d").is_none());
        assert!(!serialized
            .to_string()
            .contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
    }

    #[test]
    fn public_jwk_rejects_private_members() {
        let err = PublicJwk::parse(RAW_JWK).expect_err("private member must reject");
        assert!(matches!(err, JwkError::Invalid(_)));

        const MARKER: &str = "PRIVATE_MEMBER_VALUE_MUST_NOT_LEAK";
        for member in ["d", "k", "oth", "\\u006b"] {
            let raw = format!(
                r#"{{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","{member}":"{MARKER}"}}"#
            );
            assert!(matches!(PublicJwk::parse(&raw), Err(JwkError::Invalid(_))));
            let typed_error = serde_json::from_str::<PublicJwk>(&raw)
                .expect_err("typed public-key decoding must reject private material");
            let diagnostic = typed_error.to_string();
            assert!(diagnostic.contains("public JWK contains private material"));
            assert!(!diagnostic.contains(MARKER));
        }

        let duplicate = r#"{"kty":"OKP","kty":"EC","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc"}"#;
        assert!(serde_json::from_str::<PublicJwk>(duplicate).is_err());
    }

    #[test]
    fn raw_jwk_parsers_enforce_the_shared_byte_limit() {
        let oversized = " ".repeat(MAX_JWK_JSON_BYTES + 1);
        assert!(matches!(
            PrivateJwk::parse(&oversized),
            Err(JwkError::JsonTooLarge)
        ));
        assert!(matches!(
            PublicJwk::parse(&oversized),
            Err(JwkError::JsonTooLarge)
        ));

        let oversized_did = format!("did:jwk:{}", "A".repeat(MAX_DID_JWK_IDENTIFIER_BYTES + 1));
        assert_eq!(parse_did_jwk(&oversized_did), Err(DidError::InvalidDidJwk));
    }

    #[test]
    fn jwk_parse_allows_standard_public_metadata_outside_did_jwk() {
        let public = PublicJwk::parse(
            r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1","use":"sig","key_ops":["verify"]}"#,
        )
        .expect("public JWK metadata is allowed");

        assert_eq!(public.kid.as_deref(), Some("did:web:issuer.test#key-1"));
        assert_eq!(public.alg.as_deref(), Some("EdDSA"));

        let private = PrivateJwk::parse(
            r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1","use":"sig","key_ops":["sign"]}"#,
        )
        .expect("private JWK metadata is allowed");

        assert_eq!(private.kid.as_deref(), Some("did:web:issuer.test#key-1"));
        assert_eq!(private.alg.as_deref(), Some("EdDSA"));
    }

    #[test]
    fn eddsa_sign_and_verify_round_trip() {
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let public = private.public();
        let payload = b"registry-platform";
        let signature = sign(payload, &private).expect("payload signs");

        verify(payload, &signature, &public).expect("signature verifies");
        assert!(verify(b"tampered", &signature, &public).is_err());
    }

    #[tokio::test]
    async fn local_jwk_signer_signs_and_exposes_public_metadata() {
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let signer = LocalJwkSigner::new(private).expect("local signer builds");
        let payload = b"registry-platform-provider";
        let signature = signer.sign(payload).await.expect("payload signs");

        assert_eq!(signer.algorithm(), SigningAlgorithm::EdDsa);
        assert_eq!(signer.key_id(), "did:web:issuer.test#key-1");
        let public = signer.public_jwk();
        verify(payload, &signature, &public).expect("signature verifies");
        let public_json = serde_json::to_value(public).expect("public jwk serializes");
        assert!(public_json.get("d").is_none());
    }

    #[test]
    fn local_jwk_signer_requires_non_empty_key_id() {
        let mut private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        private.kid = None;
        assert!(matches!(
            LocalJwkSigner::new(private),
            Err(SigningError::MissingKeyId)
        ));

        let mut private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        private.kid = Some(String::new());
        assert!(matches!(
            LocalJwkSigner::new(private),
            Err(SigningError::MissingKeyId)
        ));
    }

    #[test]
    fn local_jwk_signer_validates_private_material_at_construction() {
        let mut private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        private.d = Some("not-base64url".to_string());

        assert!(matches!(
            LocalJwkSigner::new(private),
            Err(SigningError::InvalidKey(JwkError::Invalid("d")))
        ));
    }

    #[test]
    fn local_jwk_signer_debug_redacts_private_material() {
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let signer = LocalJwkSigner::new(private).expect("local signer builds");
        let debug = format!("{signer:?}");

        assert!(debug.contains("LocalJwkSigner"));
        assert!(debug.contains("did:web:issuer.test#key-1"));
        assert!(!debug.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
    }

    #[cfg(all(unix, feature = "transit"))]
    #[tokio::test]
    async fn transit_signer_uses_the_common_vault_openbao_es256_wire_contract() {
        const METADATA_PATH: &str = "/v1/registry-transit/keys/custody-key";
        const SIGN_PATH: &str = "/v1/registry-transit/sign/custody-key/sha2-256";
        let private = PrivateJwk::parse(P256_JWK).expect("P-256 private JWK");
        let public = private.public();
        let payload = &[0xfb, 0xff];
        assert_eq!(
            transit_request(payload, 7)["input"],
            "24/tVBWa/kCs5bSdcCJZ/YjJxACTBxgYJEh7qrXGveo="
        );
        assert_ne!(transit_request(payload, 7)["input"], "+/8=");
        let replies = vec![
            transit_reply(
                "GET",
                METADATA_PATH,
                None,
                transit_metadata(&p256_public_pem(&private)),
            ),
            transit_reply(
                "POST",
                SIGN_PATH,
                Some(transit_request(TRANSIT_SELF_TEST_MESSAGE, 7)),
                transit_signature(&private, TRANSIT_SELF_TEST_MESSAGE, 7),
            ),
            transit_reply(
                "POST",
                SIGN_PATH,
                Some(transit_request(payload, 7)),
                transit_signature(&private, payload, 7),
            ),
        ];
        let (directory, socket_path, server) = spawn_transit_mock(replies);
        let socket_marker = socket_path.display().to_string();
        let config = TransitSignerConfig::new(
            socket_path,
            "registry-transit",
            "custody-key",
            7,
            public.clone(),
            Duration::from_secs(2),
        )
        .expect("Transit config");
        let config_debug = format!("{config:?}");
        assert!(!config_debug.contains(&socket_marker));
        assert!(!config_debug.contains("registry-transit"));
        assert!(!config_debug.contains("custody-key"));

        let signer = TransitSigner::initialize(config)
            .await
            .expect("Transit signer initializes");
        assert_eq!(signer.algorithm(), SigningAlgorithm::Es256);
        assert_eq!(signer.key_id(), "did:web:issuer.test#p256-key-1");
        assert_eq!(signer.public_jwk(), public);
        assert_eq!(signer.readiness(), KeyReadiness::Ready);
        let signature = signer.sign(payload).await.expect("Transit signs");
        assert_eq!(signature.len(), 64);
        verify(payload, &signature, &signer.public_jwk()).expect("signature verifies");
        assert_eq!(signer.readiness(), KeyReadiness::Ready);

        server.await.expect("mock Transit server completed");
        drop(directory);
    }

    #[cfg(all(unix, feature = "transit"))]
    #[tokio::test]
    async fn transit_signer_accepts_vault_native_metadata_and_sign_response_fixtures() {
        const METADATA_PATH: &str = "/v1/vault-transit/keys/evidence-key";
        const SIGN_PATH: &str = "/v1/vault-transit/sign/evidence-key/sha2-256";
        let private = PrivateJwk::parse(P256_JWK).expect("P-256 private JWK");
        let replies = vec![
            transit_reply(
                "GET",
                METADATA_PATH,
                None,
                vault_transit_metadata_response_fixture(&p256_public_pem(&private)),
            ),
            transit_reply(
                "POST",
                SIGN_PATH,
                Some(transit_request(TRANSIT_SELF_TEST_MESSAGE, 7)),
                vault_transit_sign_response_fixture(&private, TRANSIT_SELF_TEST_MESSAGE, 7),
            ),
        ];
        let (directory, socket_path, server) = spawn_transit_mock(replies);
        let signer = TransitSigner::initialize(
            TransitSignerConfig::new(
                socket_path,
                "vault-transit",
                "evidence-key",
                7,
                private.public(),
                Duration::from_secs(1),
            )
            .expect("Vault Transit config"),
        )
        .await
        .expect("Vault Transit fixtures initialize the signer");

        assert_eq!(signer.readiness(), KeyReadiness::Ready);
        server.await.expect("mock Vault Transit server completed");
        drop(directory);
    }

    #[cfg(all(unix, feature = "transit"))]
    #[tokio::test]
    async fn transit_signer_accepts_openbao_native_metadata_and_sign_response_fixtures() {
        const METADATA_PATH: &str = "/v1/openbao-transit/keys/evidence-key";
        const SIGN_PATH: &str = "/v1/openbao-transit/sign/evidence-key/sha2-256";
        let private = PrivateJwk::parse(P256_JWK).expect("P-256 private JWK");
        let replies = vec![
            transit_reply(
                "GET",
                METADATA_PATH,
                None,
                openbao_transit_metadata_response_fixture(&p256_public_pem(&private)),
            ),
            transit_reply(
                "POST",
                SIGN_PATH,
                Some(transit_request(TRANSIT_SELF_TEST_MESSAGE, 7)),
                openbao_transit_sign_response_fixture(&private, TRANSIT_SELF_TEST_MESSAGE, 7),
            ),
        ];
        let (directory, socket_path, server) = spawn_transit_mock(replies);
        let signer = TransitSigner::initialize(
            TransitSignerConfig::new(
                socket_path,
                "openbao-transit",
                "evidence-key",
                7,
                private.public(),
                Duration::from_secs(1),
            )
            .expect("OpenBao Transit config"),
        )
        .await
        .expect("OpenBao Transit fixtures initialize the signer");

        assert_eq!(signer.readiness(), KeyReadiness::Ready);
        server.await.expect("mock OpenBao Transit server completed");
        drop(directory);
    }

    #[cfg(feature = "transit")]
    #[test]
    fn transit_signer_config_rejects_unpinned_or_non_es256_bindings() {
        let public = PrivateJwk::parse(P256_JWK)
            .expect("P-256 private JWK")
            .public();
        let build = |socket: &str,
                     mount: &str,
                     name: &str,
                     version: u32,
                     key: PublicJwk,
                     timeout: Duration| {
            TransitSignerConfig::new(socket, mount, name, version, key, timeout)
        };
        assert!(build(
            "relative.sock",
            "transit",
            "key",
            7,
            public.clone(),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(build(
            "/run/transit.sock",
            "../transit",
            "key",
            7,
            public.clone(),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(build(
            "/run/transit.sock",
            "transit",
            "key/name",
            7,
            public.clone(),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(build(
            "/run/transit.sock",
            "transit",
            "key",
            0,
            public.clone(),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(build(
            "/run/transit.sock",
            "transit",
            "key",
            7,
            public.clone(),
            Duration::ZERO
        )
        .is_err());
        assert!(build(
            "/run/transit.sock",
            "transit",
            "key",
            7,
            public,
            MAX_TRANSIT_REQUEST_TIMEOUT + Duration::from_millis(1)
        )
        .is_err());
        assert!(build(
            "/run/transit.sock",
            "transit",
            "key",
            7,
            PrivateJwk::parse(RAW_JWK).expect("Ed25519 JWK").public(),
            Duration::from_secs(1)
        )
        .is_err());
    }

    #[cfg(all(unix, feature = "transit"))]
    #[tokio::test]
    async fn transit_signer_rejects_unsafe_or_mismatched_metadata() {
        const METADATA_PATH: &str = "/v1/transit/keys/key";
        let private = PrivateJwk::parse(P256_JWK).expect("P-256 private JWK");
        let public = private.public();
        let pem = p256_public_pem(&private);
        let mut cases = Vec::new();
        for field in ["derived", "exportable", "allow_plaintext_backup"] {
            let mut metadata = transit_metadata(&pem);
            metadata["data"][field] = Value::Bool(true);
            cases.push(metadata);
        }
        let mut wrong_type = transit_metadata(&pem);
        wrong_type["data"]["type"] = Value::String("ed25519".to_owned());
        cases.push(wrong_type);
        let mut no_signing = transit_metadata(&pem);
        no_signing["data"]["supports_signing"] = Value::Bool(false);
        cases.push(no_signing);
        let mut version_too_old = transit_metadata(&pem);
        version_too_old["data"]["min_encryption_version"] = json!(8);
        cases.push(version_too_old);
        let mut missing_version = transit_metadata(&pem);
        missing_version["data"]["keys"]
            .as_object_mut()
            .expect("keys object")
            .remove("7");
        cases.push(missing_version);

        let other_scalar = [42_u8; 32];
        let other_signing = P256SigningKey::from_slice(&other_scalar).expect("second P-256 key");
        let other_point = other_signing.verifying_key().to_encoded_point(false);
        let other_public =
            P256PublicKey::from_sec1_bytes(other_point.as_bytes()).expect("second public key");
        let mut wrong_public = transit_metadata(
            &other_public
                .to_public_key_pem(LineEnding::LF)
                .expect("second public PEM"),
        );
        wrong_public["data"]["latest_version"] = json!(7);
        cases.push(wrong_public);

        for metadata in cases {
            let replies = vec![transit_reply("GET", METADATA_PATH, None, metadata)];
            let (directory, socket_path, server) = spawn_transit_mock(replies);
            let config = TransitSignerConfig::new(
                socket_path,
                "transit",
                "key",
                7,
                public.clone(),
                Duration::from_secs(1),
            )
            .expect("Transit config");
            let error = TransitSigner::initialize(config)
                .await
                .expect_err("unsafe Transit metadata must reject");
            assert!(error.to_string().contains("metadata is invalid"));
            server.await.expect("mock Transit server completed");
            drop(directory);
        }
    }

    #[cfg(all(unix, feature = "transit"))]
    #[tokio::test]
    async fn transit_signer_fails_closed_without_leaking_provider_responses_then_recovers() {
        const METADATA_PATH: &str = "/v1/transit/keys/key";
        const SIGN_PATH: &str = "/v1/transit/sign/key/sha2-256";
        const CANARY: &str = "PRIVATE_PROVIDER_DIAGNOSTIC_CANARY";
        let private = PrivateJwk::parse(P256_JWK).expect("P-256 private JWK");
        let public = private.public();
        let payload = b"protected.payload";
        let replies = vec![
            transit_reply(
                "GET",
                METADATA_PATH,
                None,
                transit_metadata(&p256_public_pem(&private)),
            ),
            transit_reply(
                "POST",
                SIGN_PATH,
                Some(transit_request(TRANSIT_SELF_TEST_MESSAGE, 7)),
                transit_signature(&private, TRANSIT_SELF_TEST_MESSAGE, 7),
            ),
            transit_reply(
                "POST",
                SIGN_PATH,
                Some(transit_request(payload, 7)),
                json!({"data": {"signature": format!("vault:v8:{CANARY}")}}),
            ),
            transit_reply(
                "POST",
                SIGN_PATH,
                Some(transit_request(payload, 7)),
                transit_signature(&private, payload, 7),
            ),
        ];
        let (directory, socket_path, server) = spawn_transit_mock(replies);
        let signer = TransitSigner::initialize(
            TransitSignerConfig::new(
                socket_path,
                "transit",
                "key",
                7,
                public,
                Duration::from_secs(1),
            )
            .expect("Transit config"),
        )
        .await
        .expect("Transit signer initializes");

        let error = signer
            .sign(payload)
            .await
            .expect_err("wrong version rejects");
        assert!(!error.to_string().contains(CANARY));
        assert_eq!(signer.readiness(), KeyReadiness::NotReady);
        signer.sign(payload).await.expect("provider recovery signs");
        assert_eq!(signer.readiness(), KeyReadiness::Ready);

        server.await.expect("mock Transit server completed");
        drop(directory);
    }

    #[cfg(all(unix, feature = "transit"))]
    #[tokio::test]
    async fn transit_signer_bounds_time_and_response_bytes() {
        const METADATA_PATH: &str = "/v1/transit/keys/key";
        let private = PrivateJwk::parse(P256_JWK).expect("P-256 private JWK");
        let public = private.public();
        let delayed = MockTransitReply {
            method: "GET",
            path: METADATA_PATH,
            body: None,
            status: 200,
            response: serde_json::to_vec(&transit_metadata(&p256_public_pem(&private)))
                .expect("metadata JSON"),
            delay: Duration::from_millis(50),
        };
        let (directory, socket_path, server) = spawn_transit_mock(vec![delayed]);
        let config = TransitSignerConfig::new(
            socket_path,
            "transit",
            "key",
            7,
            public.clone(),
            Duration::from_millis(5),
        )
        .expect("Transit config");
        let timeout = TransitSigner::initialize(config)
            .await
            .expect_err("slow Transit metadata times out");
        assert!(timeout.to_string().contains("metadata is unavailable"));
        server.await.expect("slow mock completed");
        drop(directory);

        let oversized = MockTransitReply {
            method: "GET",
            path: METADATA_PATH,
            body: None,
            status: 200,
            response: vec![b'x'; MAX_TRANSIT_RESPONSE_BYTES + 1],
            delay: Duration::ZERO,
        };
        let (directory, socket_path, server) = spawn_transit_mock(vec![oversized]);
        let config = TransitSignerConfig::new(
            socket_path,
            "transit",
            "key",
            7,
            public,
            Duration::from_secs(1),
        )
        .expect("Transit config");
        let oversized = TransitSigner::initialize(config)
            .await
            .expect_err("oversized Transit metadata rejects");
        assert!(oversized.to_string().contains("metadata is unavailable"));
        server.await.expect("oversized mock completed");
        drop(directory);
    }

    #[test]
    fn external_signing_error_messages_are_bounded_and_single_line() {
        let message = format!("{}{}", "provider unavailable\n", "x".repeat(512));
        let err = SigningError::external(message);
        let rendered = err.to_string();

        assert!(!rendered.contains('\n'));
        assert!(rendered.len() <= 220, "{rendered}");
    }

    #[test]
    fn eddsa_may_be_inferred_from_okp_ed25519_without_alg() {
        let private = PrivateJwk::parse(
            r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc"}"#,
        )
        .expect("Ed25519 JWK parses without alg");

        assert_eq!(
            private.algorithm().expect("algorithm"),
            SigningAlgorithm::EdDsa
        );
    }

    #[test]
    fn private_jwk_parser_rejects_unsupported_secret_members() {
        const MARKER: &str = "UNSUPPORTED_PRIVATE_VALUE_MUST_NOT_LEAK";
        for member in ["k", "oth", "\\u006b"] {
            let raw = RAW_JWK.replacen(
                r#""kty":"OKP""#,
                &format!(r#""kty":"OKP","{member}":"{MARKER}""#),
                1,
            );
            let error =
                PrivateJwk::parse(&raw).expect_err("unsupported private-key material must reject");
            let diagnostic = format!("{error:?} {error}");
            assert!(diagnostic.contains("unsupported private JWK material"));
            assert!(!diagnostic.contains(MARKER));
        }
    }

    #[test]
    fn unsupported_signing_algorithms_are_rejected_at_parse_time() {
        let ps256 = r#"{"kty":"RSA","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4PBO8BxG7NXXjO4IhYGoOi0Lem4xXeUq7W57RtgGF4wSGZ4HAvY8R9H_JVU3tO7K0XG3L8m5vB2T2KQeJ0gJg9g4nG9QpXJYpJ2NmgH6L7ZqQHX7I4M","e":"AQAB","alg":"PS256"}"#;
        // RS256 is supported, but an RSA key missing the required private primes
        // p and q must still fail validation (not parse as a usable key).
        let rsa_without_primes = r#"{"kty":"RSA","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4PBO8BxG7NXXjO4IhYGoOi0Lem4xXeUq7W57RtgGF4wSGZ4HAvY8R9H_JVU3tO7K0XG3L8m5vB2T2KQeJ0gJg9g4nG9QpXJYpJ2NmgH6L7ZqQHX7I4M","e":"AQAB","d":"V8tFoZRiEbWqT2DF3t5R6u9vS9LqQEVtGg5oQ2Y0t5k","alg":"RS256"}"#;

        assert!(matches!(
            PublicJwk::parse(ps256),
            Err(JwkError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            PrivateJwk::parse(rsa_without_primes),
            Err(JwkError::Invalid("p"))
        ));
    }

    #[test]
    fn es256_private_and_public_jwks_parse() {
        let private = PrivateJwk::parse(P256_JWK).expect("p256 private jwk parses");
        assert_eq!(
            private.algorithm().expect("algorithm"),
            SigningAlgorithm::Es256
        );
        let public = private.public();
        let public_json = serde_json::to_value(&public).expect("public jwk serializes");

        assert_eq!(public.kty, "EC");
        assert_eq!(public.crv.as_deref(), Some("P-256"));
        assert_eq!(public.alg.as_deref(), Some("ES256"));
        assert!(public_json.get("d").is_none());
        assert!(matches!(public.algorithm(), Ok(SigningAlgorithm::Es256)));
    }

    #[test]
    fn es256_public_jwk_rejects_length_correct_off_curve_coordinates() {
        let zero_coordinate = URL_SAFE_NO_PAD.encode([0_u8; 32]);
        let candidate = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": zero_coordinate.clone(),
            "y": zero_coordinate,
            "alg": "ES256",
            "kid": "invalid-point",
        });

        assert!(matches!(
            PublicJwk::parse(&candidate.to_string()),
            Err(JwkError::Invalid("ES256 public point"))
        ));
    }

    #[test]
    fn es256_sign_then_verify_roundtrips() {
        let private = PrivateJwk::parse(P256_JWK).expect("p256 private jwk parses");
        let public = private.public();
        let payload = b"registry-notary-es256";
        let signature = sign(payload, &private).expect("payload signs");

        assert_eq!(signature.len(), 64, "ES256 JWS signatures are raw r || s");
        verify(payload, &signature, &public).expect("signature verifies");
        assert!(matches!(
            verify(b"tampered", &signature, &public),
            Err(CryptoError::InvalidSignature)
        ));
    }

    /// Backward compatibility across the aws-lc-rs move: a signature this crate
    /// produced before the migration still verifies after it.
    #[test]
    fn es256_verifies_a_signature_produced_before_the_aws_lc_rs_migration() {
        let public = PrivateJwk::parse(P256_JWK)
            .expect("p256 private jwk parses")
            .public();
        let signature = URL_SAFE_NO_PAD
            .decode(ES256_PRE_MIGRATION_SIGNATURE)
            .expect("the frozen vector decodes");

        verify(ES256_FIXED_VECTOR_PAYLOAD, &signature, &public)
            .expect("a pre-migration signature still verifies");
        assert!(matches!(
            verify(b"tampered", &signature, &public),
            Err(CryptoError::InvalidSignature)
        ));
    }

    /// Forward compatibility across the aws-lc-rs move: what this crate signs
    /// now verifies under the RustCrypto implementation that signed before it.
    ///
    /// Verifying through this crate's own `verify` would only prove one backend
    /// agrees with itself, so this reaches for `p256` directly and keeps the
    /// check independent of which backend `verify` happens to use.
    #[test]
    fn es256_signatures_verify_under_the_independent_rustcrypto_verifier() {
        let private = PrivateJwk::parse(P256_JWK).expect("p256 private jwk parses");
        let public = private.public();
        let signature = sign(ES256_FIXED_VECTOR_PAYLOAD, &private).expect("payload signs");
        assert_eq!(signature.len(), 64, "ES256 JWS signatures are raw r || s");

        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(
            &URL_SAFE_NO_PAD
                .decode(public.x.as_deref().expect("x"))
                .expect("x decodes"),
        );
        sec1[33..65].copy_from_slice(
            &URL_SAFE_NO_PAD
                .decode(public.y.as_deref().expect("y"))
                .expect("y decodes"),
        );
        let verifying_key = P256VerifyingKey::from_sec1_bytes(&sec1).expect("public point parses");
        let parsed = P256Signature::from_slice(&signature).expect("r || s parses");

        verifying_key
            .verify(ES256_FIXED_VECTOR_PAYLOAD, &parsed)
            .expect("RustCrypto verifies what aws-lc-rs signed");
    }

    /// Zero is a well-formed 32-byte string and an invalid P-256 scalar. It has
    /// to stay rejected at import, since callers rely on a key that cannot sign
    /// being refused where it is used rather than once per request.
    #[test]
    fn es256_sign_rejects_a_zero_scalar_private_key() {
        let mut key = PrivateJwk::parse(P256_JWK).expect("p256 private jwk parses");
        key.d = Some(URL_SAFE_NO_PAD.encode([0_u8; 32]));

        assert!(matches!(
            sign(ES256_FIXED_VECTOR_PAYLOAD, &key),
            Err(CryptoError::Crypto("invalid ES256 private key"))
        ));
    }

    /// Importing the pair rather than the scalar alone means a `d` sitting
    /// beside another pair's `x` and `y` no longer signs. Such a JWK used to
    /// produce a perfectly valid signature over a public half it does not
    /// describe, which no relying party holding the stated key could verify.
    #[test]
    fn es256_sign_rejects_a_private_key_whose_public_half_is_another_pair() {
        let mut key = PrivateJwk::parse(P256_JWK).expect("p256 private jwk parses");
        let other = PrivateJwk::parse(SECOND_P256_JWK).expect("second p256 private jwk parses");
        key.x = other.x.clone();
        key.y = other.y.clone();

        assert!(matches!(
            sign(ES256_FIXED_VECTOR_PAYLOAD, &key),
            Err(CryptoError::Crypto("invalid ES256 private key"))
        ));
    }

    /// The base point is the smallest valid public half, and a scalar of 1 the
    /// smallest valid private one. Point validation has to keep accepting both.
    #[test]
    fn es256_accepts_the_base_point_as_a_public_half() {
        let private = PrivateJwk::parse(SECOND_P256_JWK).expect("second p256 private jwk parses");
        let public = private.public();
        let public_json = serde_json::to_string(&public).expect("public jwk serializes");
        PublicJwk::parse(&public_json).expect("the base point is a valid public half");

        let signature = sign(ES256_FIXED_VECTOR_PAYLOAD, &private).expect("payload signs");
        verify(ES256_FIXED_VECTOR_PAYLOAD, &signature, &public).expect("signature verifies");
    }

    #[test]
    fn es384_private_and_public_jwks_parse() {
        let private = PrivateJwk::parse(P384_JWK).expect("p384 private jwk parses");
        assert_eq!(
            private.algorithm().expect("algorithm"),
            SigningAlgorithm::Es384
        );
        let public = private.public();
        let public_json = serde_json::to_value(&public).expect("public jwk serializes");

        assert_eq!(public.kty, "EC");
        assert_eq!(public.crv.as_deref(), Some("P-384"));
        assert_eq!(public.alg.as_deref(), Some("ES384"));
        assert!(public_json.get("d").is_none());
        assert!(matches!(public.algorithm(), Ok(SigningAlgorithm::Es384)));
    }

    #[test]
    fn es384_public_jwk_rejects_length_correct_off_curve_coordinates() {
        let zero_coordinate = URL_SAFE_NO_PAD.encode([0_u8; 48]);
        let candidate = json!({
            "kty": "EC",
            "crv": "P-384",
            "x": zero_coordinate.clone(),
            "y": zero_coordinate,
            "alg": "ES384",
            "kid": "invalid-point",
        });

        assert!(matches!(
            PublicJwk::parse(&candidate.to_string()),
            Err(JwkError::Invalid("ES384 public point"))
        ));

        let legitimate = serde_json::to_string(
            &PrivateJwk::parse(P384_JWK)
                .expect("p384 private jwk parses")
                .public(),
        )
        .expect("p384 public jwk serializes");
        PublicJwk::parse(&legitimate).expect("a point on P-384 is still accepted");
    }

    #[test]
    fn es384_sign_then_verify_roundtrips() {
        let private = PrivateJwk::parse(P384_JWK).expect("p384 private jwk parses");
        let public = private.public();
        let payload = b"registry-platform-es384";
        let signature = sign(payload, &private).expect("payload signs");

        assert_eq!(signature.len(), 96, "ES384 JWS signatures are raw r || s");
        verify(payload, &signature, &public).expect("signature verifies");
        assert!(matches!(
            verify(b"tampered", &signature, &public),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn es384_signing_uses_a_fresh_signature_each_call() {
        let private = PrivateJwk::parse(P384_JWK).expect("p384 private jwk parses");
        let public = private.public();
        let payload = b"registry-platform-es384-repeat";
        let first = sign(payload, &private).expect("payload signs");
        let second = sign(payload, &private).expect("payload signs again");

        assert_ne!(first, second, "ECDSA signatures carry a per-call nonce");
        verify(payload, &first, &public).expect("first signature verifies");
        verify(payload, &second, &public).expect("second signature verifies");
    }

    /// Independent known-answer check for ES384. Both halves of the vector, the
    /// key and the signature, come from OpenSSL 3.6.2 rather than from this
    /// crate.
    ///
    /// ES384 signs and verifies through aws-lc-rs on both sides, so a
    /// round-trip proves only that the crate agrees with itself. It would still
    /// pass if signing emitted an ASN.1 DER SEQUENCE where JWS wants raw
    /// `r || s`. OpenSSL does emit DER, and the frozen constant is that DER pair
    /// rewritten as raw `r || s`, so accepting it pins the JWS encoding against
    /// an outside implementation.
    ///
    /// ECDSA is randomized, so only acceptance is pinned: this signature is one
    /// of many valid ones over the payload.
    #[test]
    fn es384_accepts_an_openssl_signature_over_a_fixed_payload() {
        let public = PublicJwk::parse(ES384_OPENSSL_PUBLIC_JWK).expect("openssl p384 jwk parses");
        let signature = URL_SAFE_NO_PAD
            .decode(ES384_OPENSSL_SIGNATURE)
            .expect("the openssl vector decodes");

        assert_eq!(signature.len(), 96, "ES384 JWS signatures are raw r || s");
        verify(ES384_OPENSSL_VECTOR_PAYLOAD, &signature, &public)
            .expect("an OpenSSL ES384 signature verifies");
        assert!(matches!(
            verify(b"tampered", &signature, &public),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn es384_sign_rejects_an_out_of_range_private_scalar() {
        let mut value: Value = serde_json::from_str(P384_JWK).expect("p384 jwk json");
        value
            .as_object_mut()
            .expect("p384 jwk object")
            .insert("d".to_string(), json!(URL_SAFE_NO_PAD.encode([0_u8; 48])));
        let json = serde_json::to_string(&value).expect("p384 jwk serializes");
        let private = PrivateJwk::parse(&json).expect("zero-scalar p384 jwk still parses");

        assert!(matches!(private.algorithm(), Ok(SigningAlgorithm::Es384)));
        assert!(matches!(
            sign(b"registry-platform-es384-zero", &private),
            Err(CryptoError::Crypto(_))
        ));
    }

    /// Importing the pair rather than the scalar alone means a `d` sitting
    /// beside another pair's `x` and `y` does not sign, matching ES256. Such a
    /// JWK would otherwise produce a valid signature over a public half it does
    /// not describe, which no relying party holding the stated key can verify.
    #[test]
    fn es384_sign_rejects_a_private_key_whose_public_half_is_another_pair() {
        let other = PublicJwk::parse(ES384_OPENSSL_PUBLIC_JWK).expect("openssl p384 jwk parses");
        let mut key = PrivateJwk::parse(P384_JWK).expect("p384 private jwk parses");
        key.x = other.x.clone();
        key.y = other.y.clone();

        assert!(matches!(
            sign(b"registry-platform-es384-mismatch", &key),
            Err(CryptoError::Crypto("invalid ES384 private key"))
        ));
    }

    #[test]
    fn ec_signing_algorithms_refuse_each_other_s_curve() {
        let p256_claiming_es384 = P256_JWK.replace(r#""alg":"ES256""#, r#""alg":"ES384""#);
        let p384_claiming_es256 = P384_JWK.replace(r#""alg":"ES384""#, r#""alg":"ES256""#);

        assert!(matches!(
            PrivateJwk::parse(&p256_claiming_es384),
            Err(JwkError::Invalid("ES384 keys must be EC/P-384"))
        ));
        assert!(matches!(
            PrivateJwk::parse(&p384_claiming_es256),
            Err(JwkError::Invalid("ES256 keys must be EC/P-256"))
        ));

        let public_p256_claiming_es384 = serde_json::to_string(
            &PrivateJwk::parse(P256_JWK)
                .expect("p256 private jwk parses")
                .public(),
        )
        .expect("p256 public jwk serializes")
        .replace(r#""alg":"ES256""#, r#""alg":"ES384""#);
        let public_p384_claiming_es256 = serde_json::to_string(
            &PrivateJwk::parse(P384_JWK)
                .expect("p384 private jwk parses")
                .public(),
        )
        .expect("p384 public jwk serializes")
        .replace(r#""alg":"ES384""#, r#""alg":"ES256""#);

        assert!(matches!(
            PublicJwk::parse(&public_p256_claiming_es384),
            Err(JwkError::Invalid("ES384 keys must be EC/P-384"))
        ));
        assert!(matches!(
            PublicJwk::parse(&public_p384_claiming_es256),
            Err(JwkError::Invalid("ES256 keys must be EC/P-256"))
        ));
    }

    #[tokio::test]
    async fn local_jwk_signer_es384() {
        let private = PrivateJwk::parse(P384_JWK).expect("p384 private jwk parses");
        let signer = LocalJwkSigner::new(private).expect("local signer builds");
        let payload = b"registry-platform-es384-provider";
        let signature = signer.sign(payload).await.expect("payload signs");

        assert_eq!(signer.algorithm(), SigningAlgorithm::Es384);
        let public = signer.public_jwk();
        assert_eq!(public.kty, "EC");
        assert_eq!(public.crv.as_deref(), Some("P-384"));
        verify(payload, &signature, &public).expect("signature verifies");
    }

    fn rsa_jwk_with_alg(jwk: &str, alg: &str) -> String {
        let mut value: Value = serde_json::from_str(jwk).expect("rsa jwk json");
        value
            .as_object_mut()
            .expect("rsa jwk object")
            .insert("alg".to_string(), json!(alg));
        serde_json::to_string(&value).expect("rsa jwk serializes")
    }

    #[test]
    fn rs384_sign_then_verify_roundtrips() {
        let private = PrivateJwk::parse(&rsa_jwk_with_alg(RSA_JWK, "RS384"))
            .expect("rs384 private jwk parses");
        let public = private.public();
        let payload = b"registry-platform-rs384";
        let signature = sign(payload, &private).expect("payload signs");

        assert!(matches!(private.algorithm(), Ok(SigningAlgorithm::Rs384)));
        verify(payload, &signature, &public).expect("signature verifies");
        assert!(matches!(
            verify(b"tampered", &signature, &public),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn rs384_and_rs256_signatures_do_not_cross_verify() {
        let rs256 = PrivateJwk::parse(RSA_JWK).expect("rsa private jwk parses");
        let rs384 = PrivateJwk::parse(&rsa_jwk_with_alg(RSA_JWK, "RS384"))
            .expect("rs384 private jwk parses");
        let payload = b"registry-platform-rs384-crossover";
        let rs256_signature = sign(payload, &rs256).expect("rs256 payload signs");
        let rs384_signature = sign(payload, &rs384).expect("rs384 payload signs");

        assert!(matches!(
            verify(payload, &rs256_signature, &rs384.public()),
            Err(CryptoError::InvalidSignature)
        ));
        assert!(matches!(
            verify(payload, &rs384_signature, &rs256.public()),
            Err(CryptoError::InvalidSignature)
        ));
    }

    /// Independent known-answer check for RS384. Both halves of the vector, the
    /// key and the signature, come from OpenSSL 3.6.2 rather than from this
    /// crate.
    ///
    /// RS384 signs and verifies through aws-lc-rs on both sides, so a
    /// round-trip proves only that the crate agrees with itself. It would still
    /// pass under the wrong digest or the wrong PKCS#1 padding. RSASSA-PKCS1-v1_5
    /// is deterministic, so both directions are pinned: this crate must accept
    /// OpenSSL's signature and must emit exactly those bytes for the same key
    /// and payload.
    #[test]
    fn rs384_matches_an_openssl_signature_over_a_fixed_payload() {
        let private = PrivateJwk::parse(RS384_OPENSSL_PRIVATE_JWK).expect("openssl rsa jwk parses");
        let expected = URL_SAFE_NO_PAD
            .decode(RS384_OPENSSL_SIGNATURE)
            .expect("the openssl vector decodes");

        verify(RS384_OPENSSL_VECTOR_PAYLOAD, &expected, &private.public())
            .expect("an OpenSSL RS384 signature verifies");
        assert_eq!(
            sign(RS384_OPENSSL_VECTOR_PAYLOAD, &private).expect("payload signs"),
            expected,
            "RS384 is deterministic, so this crate must emit OpenSSL's bytes"
        );
    }

    #[test]
    fn rs384_sign_rejects_sub_2048_bit_private_key() {
        let private = PrivateJwk::parse(&rsa_jwk_with_alg(RSA_1024_JWK, "RS384"))
            .expect("1024-bit rs384 jwk parses");

        assert!(matches!(
            sign(b"registry-platform-rs384-1024", &private),
            Err(CryptoError::Crypto(_))
        ));
    }

    #[test]
    fn rs384_keys_must_be_rsa() {
        let ec_claiming_rs384 = P384_JWK.replace(r#""alg":"ES384""#, r#""alg":"RS384""#);

        assert!(matches!(
            PrivateJwk::parse(&ec_claiming_rs384),
            Err(JwkError::Invalid("RS384 keys must be RSA"))
        ));
    }

    #[tokio::test]
    async fn local_jwk_signer_rs384() {
        let private = PrivateJwk::parse(&rsa_jwk_with_alg(RSA_JWK, "RS384"))
            .expect("rs384 private jwk parses");
        let signer = LocalJwkSigner::new(private).expect("local signer builds");
        let payload = b"registry-platform-rs384-provider";
        let signature = signer.sign(payload).await.expect("payload signs");

        assert_eq!(signer.algorithm(), SigningAlgorithm::Rs384);
        let public = signer.public_jwk();
        assert_eq!(public.kty, "RSA");
        verify(payload, &signature, &public).expect("signature verifies");
    }

    #[test]
    fn every_signing_algorithm_reports_its_jws_alg_name() {
        for (algorithm, name) in [
            (SigningAlgorithm::EdDsa, "EdDSA"),
            (SigningAlgorithm::Es256, "ES256"),
            (SigningAlgorithm::Rs256, "RS256"),
            (SigningAlgorithm::Es384, "ES384"),
            (SigningAlgorithm::Rs384, "RS384"),
        ] {
            assert_eq!(algorithm.jwa_name(), name);
        }
    }

    fn rsa_public_json() -> String {
        let public = PrivateJwk::parse(RSA_JWK)
            .expect("rsa private jwk parses")
            .public();
        serde_json::to_string(&public).expect("rsa public jwk serializes")
    }

    #[test]
    fn rs256_sign_then_verify_roundtrips() {
        let private = PrivateJwk::parse(RSA_JWK).expect("rsa private jwk parses");
        let public = private.public();
        let payload = b"registry-notary-rs256";
        let signature = sign(payload, &private).expect("payload signs");

        verify(payload, &signature, &public).expect("signature verifies");
    }

    #[test]
    fn rs256_verify_rejects_tampered_payload() {
        let private = PrivateJwk::parse(RSA_JWK).expect("rsa private jwk parses");
        let public = private.public();
        let signature = sign(b"registry-notary-rs256", &private).expect("payload signs");

        assert!(matches!(
            verify(b"tampered", &signature, &public),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn rs256_verify_rejects_wrong_signature() {
        let private = PrivateJwk::parse(RSA_JWK).expect("rsa private jwk parses");
        let public = private.public();
        let payload = b"registry-notary-rs256";
        let mut signature = sign(payload, &private).expect("payload signs");
        let last = signature.len() - 1;
        signature[last] ^= 0x01;

        assert!(matches!(
            verify(payload, &signature, &public),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn rs256_private_jwk_parses_and_reports_rs256() {
        let private = PrivateJwk::parse(RSA_JWK).expect("rsa private jwk parses");
        assert!(matches!(private.algorithm(), Ok(SigningAlgorithm::Rs256)));
    }

    #[test]
    fn rs256_private_jwk_requires_crt_parameters() {
        let mut value: Value = serde_json::from_str(RSA_JWK).expect("rsa jwk json");
        value.as_object_mut().expect("rsa jwk object").remove("dp");
        let json = serde_json::to_string(&value).expect("rsa jwk serializes");

        assert!(matches!(
            PrivateJwk::parse(&json),
            Err(JwkError::Invalid("dp"))
        ));
    }

    #[test]
    fn rs256_sign_rejects_sub_2048_bit_private_key() {
        let private = PrivateJwk::parse(RSA_1024_JWK).expect("1024-bit rsa jwk parses");

        assert!(matches!(
            sign(b"registry-notary-rs256-1024", &private),
            Err(CryptoError::Crypto(_))
        ));
    }

    #[test]
    fn rs256_verify_rejects_sub_2048_bit_public_key() {
        let public = PrivateJwk::parse(RSA_1024_JWK)
            .expect("1024-bit rsa jwk parses")
            .public();
        let signature = URL_SAFE_NO_PAD
            .decode(RSA_1024_SIGNATURE)
            .expect("1024-bit rsa signature fixture decodes");

        assert!(matches!(
            verify(b"registry-notary-rs256-1024", &signature, &public),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn rs256_public_jwk_parses() {
        let public = PublicJwk::parse(&rsa_public_json()).expect("rsa public jwk parses");
        assert_eq!(public.kty, "RSA");
        assert!(matches!(public.algorithm(), Ok(SigningAlgorithm::Rs256)));
    }

    #[test]
    fn rs256_public_jwk_rejects_private_members() {
        let public = PrivateJwk::parse(RSA_JWK)
            .expect("rsa private jwk parses")
            .public();
        let mut value = serde_json::to_value(&public).expect("rsa public jwk serializes");
        value
            .as_object_mut()
            .expect("object")
            .insert("p".to_string(), json!("not-allowed-on-public"));
        let json = serde_json::to_string(&value).expect("json serializes");

        let err = PublicJwk::parse(&json).expect_err("private member must reject");
        assert!(matches!(err, JwkError::Invalid(_)));
    }

    #[test]
    fn rsa_private_public_drops_private_members() {
        let public = PrivateJwk::parse(RSA_JWK)
            .expect("rsa private jwk parses")
            .public();
        let public_json = serde_json::to_value(&public).expect("rsa public jwk serializes");

        assert!(public_json.get("n").is_some());
        assert!(public_json.get("e").is_some());
        for member in ["d", "p", "q", "dp", "dq", "qi"] {
            assert!(
                public_json.get(member).is_none(),
                "public projection leaked {member}"
            );
        }
    }

    #[test]
    fn rsa_jwk_without_alg_is_unsupported() {
        let mut value: Value = serde_json::from_str(RSA_JWK).expect("rsa jwk json");
        value.as_object_mut().expect("object").remove("alg");
        let json = serde_json::to_string(&value).expect("json serializes");

        assert!(matches!(
            PrivateJwk::parse(&json),
            Err(JwkError::UnsupportedAlgorithm)
        ));
    }

    #[tokio::test]
    async fn local_jwk_signer_rs256() {
        let private = PrivateJwk::parse(RSA_JWK).expect("rsa private jwk parses");
        let signer = LocalJwkSigner::new(private).expect("local signer builds");
        let payload = b"registry-notary-rs256-provider";
        let signature = signer.sign(payload).await.expect("payload signs");

        assert_eq!(signer.algorithm(), SigningAlgorithm::Rs256);
        let public = signer.public_jwk();
        assert_eq!(public.kty, "RSA");
        verify(payload, &signature, &public).expect("signature verifies");
    }

    #[tokio::test]
    async fn local_jwk_signer_es256() {
        let private = PrivateJwk::parse(P256_JWK).expect("p256 private jwk parses");
        let signer = LocalJwkSigner::new(private).expect("local signer builds");
        let payload = b"registry-notary-es256-provider";
        let signature = signer.sign(payload).await.expect("payload signs");

        assert_eq!(signer.algorithm(), SigningAlgorithm::Es256);
        let public = signer.public_jwk();
        assert_eq!(public.kty, "EC");
        assert_eq!(public.crv.as_deref(), Some("P-256"));
        verify(payload, &signature, &public).expect("signature verifies");
    }

    #[test]
    fn private_jwk_debug_redacts_rsa_private_members() {
        let private = PrivateJwk::parse(RSA_JWK).expect("rsa private jwk parses");
        let debug = format!("{private:?}");

        assert!(debug.contains("[redacted]"));
        let d = private.d.as_deref().expect("d");
        let p = private.p.as_deref().expect("p");
        let q = private.q.as_deref().expect("q");
        assert!(!debug.contains(d));
        assert!(!debug.contains(p));
        assert!(!debug.contains(q));
    }

    #[test]
    #[ignore = "micro-benchmark: run explicitly with `cargo test -- --ignored` to measure local sign/verify latency"]
    fn eddsa_sign_microbench() {
        use std::time::Instant;
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let payload = b"registry-platform-bench-payload";
        let iterations = 1000;
        let start = Instant::now();
        for _ in 0..iterations {
            sign(payload, &private).expect("sign");
        }
        let elapsed = start.elapsed();
        println!(
            "sign: {} iterations in {:?} = {:.1} µs/op",
            iterations,
            elapsed,
            elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64
        );
    }

    #[test]
    #[ignore = "micro-benchmark: run explicitly with `cargo test -- --ignored` to measure local sign/verify latency"]
    fn eddsa_verify_microbench() {
        use std::time::Instant;
        let private = PrivateJwk::parse(RAW_JWK).expect("private jwk parses");
        let public = private.public();
        let payload = b"registry-platform-bench-payload";
        let signature = sign(payload, &private).expect("sign");
        let iterations = 1000;
        let start = Instant::now();
        for _ in 0..iterations {
            verify(payload, &signature, &public).expect("verify");
        }
        let elapsed = start.elapsed();
        println!(
            "verify: {} iterations in {:?} = {:.1} µs/op",
            iterations,
            elapsed,
            elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64
        );
    }

    #[test]
    fn validate_did_returns_missing_prefix_for_non_did_strings() {
        assert_eq!(
            validate_did("not-a-did", &[DidMethod::Web]),
            Err(DidError::MissingPrefix)
        );
        assert_eq!(
            validate_did("web:example.org", &[DidMethod::Web]),
            Err(DidError::MissingPrefix)
        );
    }

    #[test]
    fn validate_did_returns_method_not_allowed_for_unlisted_method() {
        assert_eq!(
            validate_did("did:web:example.org", &[DidMethod::Key]),
            Err(DidError::MethodNotAllowed)
        );
        assert_eq!(
            validate_did("did:key:z6MkiTBz", &[DidMethod::Web]),
            Err(DidError::MethodNotAllowed)
        );
    }

    #[test]
    fn validate_did_returns_unsupported_method_for_unknown_scheme() {
        assert_eq!(
            validate_did(
                "did:unknown:identifier",
                &[DidMethod::Web, DidMethod::Key, DidMethod::Jwk]
            ),
            Err(DidError::UnsupportedMethod)
        );
        assert_eq!(
            validate_did("did:ethr:0xabc", &[]),
            Err(DidError::UnsupportedMethod)
        );
    }

    #[test]
    fn validate_did_accepts_allowed_web_and_key_methods() {
        let did = validate_did(
            "did:web:example.org:issuers:alpha#key-1",
            &[DidMethod::Web, DidMethod::Key],
        )
        .expect("did:web validates");

        assert_eq!(did.method, DidMethod::Web);
        assert_eq!(did.identifier, "example.org:issuers:alpha");
        assert_eq!(did.fragment.as_deref(), Some("key-1"));

        validate_did("did:key:z6MkiTBz", &[DidMethod::Key]).expect("did:key validates");
    }

    #[test]
    fn did_jwk_round_trips_public_jwk_and_rejects_private_material() {
        let public = PrivateJwk::parse(RAW_JWK)
            .expect("private jwk parses")
            .public();
        let did = did_jwk_from_public_jwk(&public).expect("did:jwk encodes");
        let validated = validate_did(&did, &[DidMethod::Jwk]).expect("did:jwk validates");
        let parsed = parse_did_jwk(&did).expect("did:jwk parses");

        assert_eq!(validated.method, DidMethod::Jwk);
        assert_eq!(parsed.kty, public.kty);
        assert_eq!(parsed.crv, public.crv);
        assert_eq!(parsed.x, public.x);
        assert_eq!(parsed.alg, None);
        assert_eq!(parsed.kid, None);

        let private_payload = URL_SAFE_NO_PAD.encode(
            canonicalize_json(&json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
                "d": "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"
            }))
            .expect("canonical json"),
        );
        let private_did = format!("did:jwk:{private_payload}");
        assert_eq!(parse_did_jwk(&private_did), Err(DidError::InvalidDidJwk));
    }

    #[test]
    fn did_jwk_accepts_public_metadata_and_rejects_unsupported_members() {
        let public = PrivateJwk::parse(RAW_JWK)
            .expect("private jwk parses")
            .public();
        let wallet_did = format!(
            "did:jwk:{}",
            URL_SAFE_NO_PAD.encode(
                br#"{"x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#
            )
        );
        let parsed = parse_did_jwk(&wallet_did).expect("wallet did:jwk parses");
        assert_eq!(parsed.kty, public.kty);
        assert_eq!(parsed.crv, public.crv);
        assert_eq!(parsed.x, public.x);
        assert_eq!(parsed.alg, None);
        assert_eq!(parsed.kid, None);

        let unsupported_member = format!(
            "did:jwk:{}",
            URL_SAFE_NO_PAD.encode(
                canonicalize_json(&json!({
                    "alg": "EdDSA",
                    "crv": "Ed25519",
                    "kid": "did:web:issuer.test#key-1",
                    "kty": "OKP",
                    "use": "sig",
                    "x": public.x.as_deref().expect("x"),
                }))
                .expect("canonical json")
            )
        );
        assert_eq!(
            parse_did_jwk(&unsupported_member),
            Err(DidError::InvalidDidJwk)
        );

        let duplicate_member = format!(
            "did:jwk:{}",
            URL_SAFE_NO_PAD.encode(
                br#"{"kty":"OKP","\u006bty":"EC","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc"}"#
            )
        );
        assert_eq!(
            parse_did_jwk(&duplicate_member),
            Err(DidError::InvalidDidJwk)
        );
    }

    #[test]
    fn validate_did_web_rejects_localhost_ips_and_path_traversal() {
        assert!(validate_did_web("did:web:localhost").is_err());
        assert!(validate_did_web("did:web:127.0.0.1").is_err());
        assert!(validate_did_web("did:web:example.org:..:issuer").is_err());
        assert!(validate_did_web("did:web:example.org:%2e%2e:issuer").is_err());
    }

    #[test]
    fn did_web_https_issuer_binding_accepts_matching_https_host() {
        validate_did_web_https_issuer_binding(
            "did:web:agency-a.example.gov",
            "https://agency-a.example.gov",
        )
        .expect("matching HTTPS issuer host binds");
        validate_did_web_https_issuer_binding(
            "did:web:agency-a.example.gov:issuers:alpha#key-1",
            "https://AGENCY-A.example.gov/federation/v1",
        )
        .expect("matching HTTPS issuer host binds case-insensitively");
    }

    #[test]
    fn did_web_https_issuer_binding_rejects_non_https_and_mismatch() {
        assert_eq!(
            validate_did_web_https_issuer_binding(
                "did:web:agency-a.example.gov",
                "http://agency-a.example.gov"
            ),
            Err(DidError::IssuerMustUseHttps)
        );
        assert_eq!(
            validate_did_web_https_issuer_binding(
                "did:web:agency-a.example.gov",
                "https://agency-b.example.gov"
            ),
            Err(DidError::IssuerHostMismatch)
        );
        assert_eq!(
            validate_did_web_https_issuer_binding("did:key:z6MkiTBz", "https://example.gov"),
            Err(DidError::UnsupportedMethod)
        );
    }

    #[test]
    fn hmac_sha256_base64url_no_pad_matches_fixed_vector() {
        assert_eq!(
            hmac_sha256_base64url_no_pad(b"key", b"The quick brown fox jumps over the lazy dog"),
            "97yD9DBThCSxMpjmqm-xQ-9NWaFJRhdZl0edvC0aPNg"
        );
    }

    #[test]
    fn key_provider_kind_serializes_shared_labels() {
        let cases = [
            (KeyProviderKind::LocalJwkEnv, "local_jwk_env"),
            (KeyProviderKind::FileWatch, "file_watch"),
            (KeyProviderKind::Pkcs11, "pkcs11"),
            (KeyProviderKind::LocalPkcs12File, "local_pkcs12_file"),
            (KeyProviderKind::Kms, "kms"),
            (KeyProviderKind::WorkloadIdentity, "workload_identity"),
        ];

        for (kind, expected) in cases {
            let serialized = serde_json::to_string(&kind).expect("provider kind serializes");
            assert_eq!(serialized, format!("\"{expected}\""));
            let decoded: KeyProviderKind =
                serde_json::from_str(&serialized).expect("provider kind deserializes");
            assert_eq!(decoded, kind);
            assert_eq!(decoded.as_str(), expected);
        }
    }

    #[test]
    fn key_status_serializes_shared_labels_and_capabilities() {
        let cases = [
            (KeyStatus::Active, "active", true, true),
            (KeyStatus::PublishOnly, "publish_only", false, true),
            (KeyStatus::Disabled, "disabled", false, false),
        ];

        for (status, expected, may_sign, may_publish) in cases {
            let serialized = serde_json::to_string(&status).expect("key status serializes");
            assert_eq!(serialized, format!("\"{expected}\""));
            let decoded: KeyStatus =
                serde_json::from_str(&serialized).expect("key status deserializes");
            assert_eq!(decoded, status);
            assert_eq!(decoded.as_str(), expected);
            assert_eq!(decoded.may_sign(), may_sign);
            assert_eq!(decoded.may_publish(), may_publish);
        }
    }

    #[test]
    fn key_readiness_serializes_shared_labels() {
        let cases = [
            (KeyReadiness::Ready, "ready", true),
            (KeyReadiness::Degraded, "degraded", false),
            (KeyReadiness::NotReady, "not_ready", false),
            (KeyReadiness::Unknown, "unknown", false),
        ];

        for (readiness, expected, is_ready) in cases {
            let serialized = serde_json::to_string(&readiness).expect("readiness serializes");
            assert_eq!(serialized, format!("\"{expected}\""));
            let decoded: KeyReadiness =
                serde_json::from_str(&serialized).expect("readiness deserializes");
            assert_eq!(decoded, readiness);
            assert_eq!(decoded.as_str(), expected);
            assert_eq!(decoded.is_ready(), is_ready);
        }
    }

    #[test]
    fn unknown_provider_status_and_readiness_values_fail_closed() {
        assert!(serde_json::from_str::<KeyProviderKind>("\"provider_plugin\"").is_err());
        assert!(serde_json::from_str::<KeyStatus>("\"retired\"").is_err());
        assert!(serde_json::from_str::<KeyReadiness>("\"warming_up\"").is_err());
    }

    #[test]
    fn readiness_gate_snapshot_distinguishes_apply_states_without_secret_material() {
        let cases = [
            (KeyReadiness::Ready, "ready", true),
            (KeyReadiness::Degraded, "degraded", false),
            (KeyReadiness::NotReady, "not_ready", false),
            (KeyReadiness::Unknown, "unknown", false),
        ];

        for (readiness, expected_label, allows_apply) in cases {
            let snapshot = KeyReadinessSnapshot {
                provider_kind: KeyProviderKind::WorkloadIdentity,
                status: KeyStatus::Active,
                readiness,
            };
            assert_eq!(snapshot.allows_live_apply(), allows_apply);
            let value = serde_json::to_value(snapshot).expect("snapshot serializes");
            assert_eq!(value["provider_kind"], "workload_identity");
            assert_eq!(value["status"], "active");
            assert_eq!(value["readiness"], expected_label);
            assert_eq!(
                value
                    .as_object()
                    .expect("snapshot is object")
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>(),
                vec!["provider_kind", "readiness", "status"]
            );
        }

        let disabled_ready = KeyReadinessSnapshot {
            provider_kind: KeyProviderKind::Kms,
            status: KeyStatus::Disabled,
            readiness: KeyReadiness::Ready,
        };
        assert!(!disabled_ready.allows_live_apply());
    }

    #[test]
    fn local_signing_provider_reports_ready_readiness() {
        let signer = LocalJwkSigner::new(PrivateJwk::parse(RAW_JWK).expect("jwk parses"))
            .expect("local signer builds");
        let provider: &dyn SigningProvider = &signer;

        assert_eq!(provider.readiness(), KeyReadiness::Ready);
    }

    #[test]
    fn pairwise_subject_ref_hash_uses_stable_canonical_input() {
        assert_eq!(
            pairwise_subject_ref_hash(
                b"federation-subject-secret",
                "did:web:agency-b.example.gov",
                "did:web:agency-a.example.gov",
                "disability_status_predicate",
                "national_id",
                "example-subject-id",
            )
            .expect("subject ref hashes"),
            "hmac-sha256:XIUcSUpspCMpOXVEeUes5EqZso47ytCAwtwAzlLpMEE"
        );
    }

    #[test]
    fn pairwise_subject_ref_hash_separates_audience_and_profile() {
        let base = pairwise_subject_ref_hash(
            b"federation-subject-secret",
            "did:web:agency-b.example.gov",
            "did:web:agency-a.example.gov",
            "disability_status_predicate",
            "national_id",
            "example-subject-id",
        )
        .expect("subject ref hashes");
        let other_audience = pairwise_subject_ref_hash(
            b"federation-subject-secret",
            "did:web:agency-c.example.gov",
            "did:web:agency-a.example.gov",
            "disability_status_predicate",
            "national_id",
            "example-subject-id",
        )
        .expect("subject ref hashes");
        let other_profile = pairwise_subject_ref_hash(
            b"federation-subject-secret",
            "did:web:agency-b.example.gov",
            "did:web:agency-a.example.gov",
            "eligibility_predicate",
            "national_id",
            "example-subject-id",
        )
        .expect("subject ref hashes");

        assert_ne!(base, other_audience);
        assert_ne!(base, other_profile);
    }

    #[test]
    fn public_jwk_thumbprint_uses_required_members_only() {
        let public = PrivateJwk::parse(RAW_JWK)
            .expect("private jwk parses")
            .public();
        assert_eq!(
            public.jkt().expect("thumbprint computes"),
            "qDygv_6SkrJ6krP3sYb0DCoEuYSYVP0ttF5m1cp_094"
        );
    }

    #[test]
    fn public_jwk_thumbprint_rejects_missing_required_members() {
        let mut public = PrivateJwk::parse(RAW_JWK)
            .expect("private jwk parses")
            .public();
        public.x = None;

        assert!(matches!(public.jkt(), Err(JwkError::Invalid("x"))));
    }

    #[test]
    fn constant_time_eq_is_available_for_callers() {
        use subtle::ConstantTimeEq;

        assert_eq!(b"a".ct_eq(b"a").unwrap_u8(), 1);
    }
}
