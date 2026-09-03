//! Access token minting.
//!
//! Every authority claim written here is read from the server-side client
//! registry. That is what makes a caller's private key a proof of *identity*
//! rather than a licence to assert whatever it likes: the caller chooses which
//! registry entry it authenticates as, and the registry chooses what that entry
//! may say.
//!
//! A delegated token is the one case where values reach a token from the
//! caller, and they arrive already reconciled against the registration by
//! [`crate::assertion`]: the actor is one the client may act as, and the
//! subject holds exactly the selector fields the registration declared, minted
//! at exactly the claim paths it declared. The registry still fixes the shape;
//! the caller only fills it in.
//!
//! Minting the subject into the token is what bounds a delegated token to one
//! person. A resource server configured to read that subject from the token
//! refuses any request carrying its own selector values, so a token issued for
//! one subject cannot be turned toward another, however the caller misbehaves.

use std::{collections::BTreeSet, path::Path, sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_config::{SecretError, SecretProvider, SecretResolver};
use registry_platform_crypto::{
    verify, KeyReadiness, LocalJwkSigner, PrivateJwk, PublicJwk, SigningAlgorithm, SigningError,
    SigningProvider, TransitSigner, TransitSignerConfig,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::{
    assertion::AuthenticatedClient,
    clients::{Delegation, RegisteredClient},
    config::{ClaimNames, MintConfig, SignerConfig},
    error::TokenError,
    ACCESS_TOKEN_TYP,
};

#[derive(Debug, Error)]
pub enum MinterError {
    #[error("the signing secret could not be resolved")]
    SigningSecret(#[source] SecretError),
    #[error("the signing key is invalid: {0}")]
    SigningKey(&'static str),
    #[error("a governed public key is invalid: {0}")]
    PublicKey(&'static str),
    #[error("the signing provider configuration is invalid: {0}")]
    SigningProviderConfiguration(#[source] SigningError),
    #[error("the signing provider initialization failed: {0}")]
    SigningProviderInitialization(#[source] SigningError),
    #[error("the signing provider self-test failed: {0}")]
    SigningProviderSelfTest(#[source] SigningError),
}

/// A minted access token and the lifetime the caller should assume.
#[derive(Debug, Serialize)]
pub struct MintedToken {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    /// The exact standard OAuth scope Mint granted. Evidence-profile tokens do
    /// not carry scopes and therefore omit this response member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip)]
    token_id: String,
    #[serde(skip)]
    signing_key_id: String,
    #[serde(skip)]
    expires_at_unix: i64,
}

impl MintedToken {
    #[must_use]
    pub(crate) fn token_id(&self) -> &str {
        &self.token_id
    }

    #[must_use]
    pub(crate) fn signing_key_id(&self) -> &str {
        &self.signing_key_id
    }

    #[must_use]
    pub(crate) fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }
}

/// Signs access tokens with the configured active key.
pub struct TokenMinter {
    issuer: String,
    audience: Value,
    lifetime_seconds: i64,
    claims: Option<ClaimNames>,
    signer: Arc<dyn SigningProvider>,
    governed_active: PublicJwk,
    recovery_probe: tokio::sync::Mutex<()>,
    jwks: Value,
}

impl std::fmt::Debug for TokenMinter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenMinter")
            .field("issuer", &self.issuer)
            .field("algorithm", &self.signer.algorithm())
            .field("key_id", &self.signer.key_id())
            .finish_non_exhaustive()
    }
}

impl TokenMinter {
    /// Load the active signing key and build the published JWK set.
    pub async fn new(config: &MintConfig) -> Result<Self, MinterError> {
        let public_keys = load_public_keys(config)?;
        let active = public_keys
            .first()
            .cloned()
            .expect("the active governed key is always present");
        let signer = build_signer(config, &active).await?;
        self_test(signer.as_ref(), &active).await?;
        let jwks = json!({ "keys": public_keys });

        let audience = configured_audience(&config.access_tokens.audiences);

        Ok(Self {
            issuer: config.issuer.clone(),
            audience,
            lifetime_seconds: config.access_tokens.lifetime_seconds as i64,
            claims: config.access_tokens.claims.clone(),
            signer,
            governed_active: active,
            recovery_probe: tokio::sync::Mutex::new(()),
            jwks,
        })
    }

    /// The public key set resource servers fetch to verify minted tokens.
    #[must_use]
    pub fn jwks(&self) -> &Value {
        &self.jwks
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Current availability of the active signing provider.
    ///
    /// Transit marks itself unavailable after a failed request. When no token
    /// traffic reaches an unready replica, the readiness route is the only
    /// remaining path that can observe provider recovery. One caller therefore
    /// repeats the bounded startup sign-and-verify proof while concurrent
    /// probes fail closed rather than queueing more provider work.
    pub async fn ready(&self) -> bool {
        if self.signer.readiness() == KeyReadiness::Ready {
            return true;
        }
        let Ok(_probe) = self.recovery_probe.try_lock() else {
            return false;
        };
        if self.signer.readiness() == KeyReadiness::Ready {
            return true;
        }
        self_test(self.signer.as_ref(), &self.governed_active)
            .await
            .is_ok()
    }

    /// Mint an access token carrying the registry's authority for `client`.
    pub async fn mint(
        &self,
        authenticated: &AuthenticatedClient,
        now: i64,
    ) -> Result<MintedToken, TokenError> {
        let client: &RegisteredClient = &authenticated.client;
        let expires_at = now + self.lifetime_seconds;
        let token_id = ulid::Ulid::new().to_string();
        let (mut claims, scope) = registered_claims(
            &self.issuer,
            &self.audience,
            self.claims.as_ref(),
            client,
            now,
            expires_at,
            &token_id,
        )?;

        if let Some(delegation) = &authenticated.delegation {
            let registered = client.delegation().ok_or_else(|| {
                TokenError::server_error("a delegation was resolved for an undelegated client")
            })?;
            // Startup refuses a registry that declares delegation without a
            // configured actor claim, so reaching here means the two disagree.
            let actor_claim = self
                .claims
                .as_ref()
                .and_then(|claims| claims.actor.as_ref())
                .ok_or_else(|| {
                    TokenError::server_error("no actor claim is configured for delegated tokens")
                })?;
            claims.insert(
                actor_claim.clone(),
                Value::String(delegation.actor().to_owned()),
            );
            write_subject_claims(&mut claims, registered, delegation)?;
        }

        let signing_input = signing_input(self.signer.key_id(), claims)?;
        let signature = self
            .signer
            .sign(signing_input.as_bytes())
            .await
            .map_err(|_| TokenError::server_error("the access token could not be signed"))?;

        Ok(MintedToken {
            access_token: format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)),
            token_type: "Bearer",
            expires_in: self.lifetime_seconds as u64,
            scope,
            token_id,
            signing_key_id: self.signer.key_id().to_owned(),
            expires_at_unix: expires_at,
        })
    }
}

/// Project the largest token response this standard registration can produce.
///
/// The shared client reads at most 16 KiB. Startup and reload use this exact
/// serialization path with maximum-width timestamps and the fixed ES256
/// signature width so Mint cannot accept authority that its paired client must
/// reject after issuance.
pub(crate) fn projected_standard_token_response_bytes(
    config: &MintConfig,
    client: &RegisteredClient,
) -> Result<u64, TokenError> {
    if client.authorization().is_none() {
        return Err(TokenError::server_error(
            "a standard token response was projected for an Evidence registration",
        ));
    }
    let lifetime = i64::try_from(config.access_tokens.lifetime_seconds)
        .map_err(|_| TokenError::server_error("the access token lifetime is invalid"))?;
    let expires_at = i64::MAX;
    let now = expires_at - lifetime;
    let token_id = "Z".repeat(26);
    let key_id = "Z".repeat(43);
    let (claims, scope) = registered_claims(
        &config.issuer,
        &configured_audience(&config.access_tokens.audiences),
        config.access_tokens.claims.as_ref(),
        client,
        now,
        expires_at,
        &token_id,
    )?;
    let signing_input = signing_input(&key_id, claims)?;
    let response = MintedToken {
        access_token: format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode([0_u8; 64])),
        token_type: "Bearer",
        expires_in: config.access_tokens.lifetime_seconds,
        scope,
        token_id,
        signing_key_id: key_id,
        expires_at_unix: expires_at,
    };
    let bytes = serde_json::to_vec(&response)
        .map_err(|_| TokenError::server_error("the token response could not be projected"))?
        .len();
    u64::try_from(bytes)
        .map_err(|_| TokenError::server_error("the token response size could not be represented"))
}

fn configured_audience(audiences: &[String]) -> Value {
    if audiences.len() == 1 {
        Value::String(audiences[0].clone())
    } else {
        Value::Array(
            audiences
                .iter()
                .map(|audience| Value::String(audience.clone()))
                .collect(),
        )
    }
}

fn registered_claims(
    issuer: &str,
    audience: &Value,
    evidence_names: Option<&ClaimNames>,
    client: &RegisteredClient,
    now: i64,
    expires_at: i64,
    token_id: &str,
) -> Result<(Map<String, Value>, Option<String>), TokenError> {
    let mut claims = Map::new();
    claims.insert("iss".to_owned(), Value::String(issuer.to_owned()));
    claims.insert("aud".to_owned(), audience.clone());
    claims.insert("iat".to_owned(), json!(now));
    claims.insert("nbf".to_owned(), json!(now));
    claims.insert("exp".to_owned(), json!(expires_at));
    claims.insert("jti".to_owned(), Value::String(token_id.to_owned()));
    // `client_id` records which registration authenticated; the principal is
    // what the resource server acts on. They are allowed to differ.
    claims.insert(
        "client_id".to_owned(),
        Value::String(client.client_id().to_owned()),
    );
    // `sub` always carries the principal so the token is meaningful to a
    // standard OAuth consumer, even when the resource server reads the
    // principal from a differently named claim.
    claims.insert(
        "sub".to_owned(),
        Value::String(client.principal().to_owned()),
    );

    let scope = if let Some(authorization) = client.authorization() {
        let scope = authorization.scopes.join(" ");
        claims.insert("scope".to_owned(), Value::String(scope.clone()));
        for (name, value) in &authorization.claims {
            claims.insert(name.clone(), value.to_json());
        }
        Some(scope)
    } else {
        let names = evidence_names
            .ok_or_else(|| TokenError::server_error("Evidence claim names are not configured"))?;
        let requester_tags = client.requester_tags().ok_or_else(|| {
            TokenError::server_error("an Evidence registration has no requester tags")
        })?;
        let evidence_audience = client.evidence_audience().ok_or_else(|| {
            TokenError::server_error("an Evidence registration has no evidence audience")
        })?;
        claims.insert(
            names.principal.clone(),
            Value::String(client.principal().to_owned()),
        );
        claims.insert(
            names.requester_tags.clone(),
            Value::Array(
                requester_tags
                    .iter()
                    .map(|tag| Value::String(tag.clone()))
                    .collect(),
            ),
        );
        claims.insert(
            names.evidence_audience.clone(),
            Value::String(evidence_audience.to_owned()),
        );
        // Evidence requires the grant id and authority together or not at all,
        // which the registry already guarantees by construction.
        if let Some(grant) = client.grant() {
            claims.insert(names.grant_id.clone(), Value::String(grant.id.clone()));
            claims.insert(
                names.grant_authority.clone(),
                Value::String(grant.authority.clone()),
            );
        }
        None
    };
    Ok((claims, scope))
}

fn signing_input(key_id: &str, claims: Map<String, Value>) -> Result<String, TokenError> {
    let header = json!({
        "alg": "ES256",
        "typ": ACCESS_TOKEN_TYP,
        "kid": key_id,
    });
    Ok(format!(
        "{}.{}",
        encode_json(&header)?,
        encode_json(&Value::Object(claims))?
    ))
}

/// Write each subject selector value at the claim path its registration
/// declared, creating the intermediate objects the path implies.
///
/// The registration's paths were checked at load time to be well formed,
/// unique, and non-nesting, so no write here can overwrite another. Anything
/// that would still collide is a bug rather than a caller's doing, and is
/// refused rather than allowed to overwrite an authority claim.
fn write_subject_claims(
    claims: &mut Map<String, Value>,
    registered: &Delegation,
    delegation: &crate::assertion::ResolvedDelegation,
) -> Result<(), TokenError> {
    let collision =
        || TokenError::server_error("a subject claim path collides with an authority claim");

    for (field, path) in &registered.subject_claims {
        let value = delegation
            .subject()
            .get(field)
            .ok_or_else(|| TokenError::server_error("a resolved subject field is missing"))?;

        let mut segments = path.split('.').peekable();
        let mut current = &mut *claims;
        while let Some(segment) = segments.next() {
            if segments.peek().is_none() {
                if current.contains_key(segment) {
                    return Err(collision());
                }
                current.insert(segment.to_owned(), value.clone());
                break;
            }
            let entry = current
                .entry(segment.to_owned())
                .or_insert_with(|| Value::Object(Map::new()));
            current = entry.as_object_mut().ok_or_else(collision)?;
        }
    }
    Ok(())
}

fn encode_json(value: &Value) -> Result<String, TokenError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| TokenError::server_error("a token component could not be serialized"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

async fn build_signer(
    config: &MintConfig,
    active: &PublicJwk,
) -> Result<Arc<dyn SigningProvider>, MinterError> {
    match &config.signer {
        SignerConfig::LocalJwk { private_key_ref } => {
            let resolver = SecretResolver::new(
                [SecretProvider::File],
                config.secret_providers.file.root.clone(),
            )
            .map_err(MinterError::SigningSecret)?;
            let secret = resolver
                .resolve(private_key_ref)
                .map_err(MinterError::SigningSecret)?;
            let text = std::str::from_utf8(secret.expose_secret())
                .map_err(|_| MinterError::SigningKey("private JWK is not UTF-8"))?;
            let private = PrivateJwk::parse(text)
                .map_err(|_| MinterError::SigningKey("not an exact ES256 private JWK"))?;
            let signer = LocalJwkSigner::new(private)
                .map_err(|_| MinterError::SigningKey("private JWK is not usable"))?;
            if signer.algorithm() != SigningAlgorithm::Es256 || signer.public_jwk() != *active {
                return Err(MinterError::SigningKey(
                    "private JWK does not match the governed active public JWK",
                ));
            }
            Ok(Arc::new(signer))
        }
        SignerConfig::Transit {
            unix_socket_path,
            mount,
            key_name,
            key_version,
            timeout_milliseconds,
        } => {
            let transit = TransitSignerConfig::new(
                unix_socket_path,
                mount,
                key_name,
                *key_version,
                active.clone(),
                Duration::from_millis(*timeout_milliseconds),
            )
            .map_err(MinterError::SigningProviderConfiguration)?;
            let signer = TransitSigner::initialize(transit)
                .await
                .map_err(MinterError::SigningProviderInitialization)?;
            Ok(Arc::new(signer))
        }
    }
}

async fn self_test(signer: &dyn SigningProvider, expected: &PublicJwk) -> Result<(), MinterError> {
    if signer.algorithm() != SigningAlgorithm::Es256
        || signer.key_id() != expected.kid.as_deref().unwrap_or_default()
        || signer.public_jwk() != *expected
    {
        return Err(MinterError::SigningKey(
            "provider metadata does not match the governed active public JWK",
        ));
    }
    let probe = b"registry-mint/signing-provider-self-test/v1";
    let signature = signer
        .sign(probe)
        .await
        .map_err(MinterError::SigningProviderSelfTest)?;
    if signature.len() != 64 || verify(probe, &signature, expected).is_err() {
        return Err(MinterError::SigningKey(
            "provider self-test signature did not verify",
        ));
    }
    Ok(())
}

fn load_public_keys(config: &MintConfig) -> Result<Vec<PublicJwk>, MinterError> {
    let revoked = config
        .signing
        .revoked_key_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let paths = std::iter::once(&config.signing.active_public_jwk_file)
        .chain(config.signing.published_public_jwk_files.iter());
    let mut keys = Vec::with_capacity(1 + config.signing.published_public_jwk_files.len());
    let mut identifiers = BTreeSet::new();
    for path in paths {
        let key = load_public_key(path)?;
        let kid = key
            .kid
            .as_deref()
            .ok_or(MinterError::PublicKey("key id is missing"))?;
        let expected_file_name = format!("{kid}.jwk.json");
        if path.file_name().and_then(|name| name.to_str()) != Some(expected_file_name.as_str()) {
            return Err(MinterError::PublicKey(
                "file name must be <thumbprint>.jwk.json",
            ));
        }
        if revoked.contains(kid) {
            return Err(MinterError::PublicKey("a published key is revoked"));
        }
        if !identifiers.insert(kid.to_owned()) {
            return Err(MinterError::PublicKey(
                "key id is repeated in the published set",
            ));
        }
        keys.push(key);
    }
    Ok(keys)
}

fn load_public_key(path: &Path) -> Result<PublicJwk, MinterError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| MinterError::PublicKey("file is unreadable"))?;
    if !metadata.is_file() {
        return Err(MinterError::PublicKey("path is not a regular file"));
    }
    let bytes = std::fs::read(path).map_err(|_| MinterError::PublicKey("file is unreadable"))?;
    if bytes.len() > registry_platform_crypto::MAX_JWK_JSON_BYTES {
        return Err(MinterError::PublicKey("document is too large"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| MinterError::PublicKey("document is not UTF-8"))?;
    let value: Value = registry_platform_crypto::parse_json_strict(&bytes)
        .map_err(|_| MinterError::PublicKey("document is not strict JSON"))?;
    let object = value
        .as_object()
        .ok_or(MinterError::PublicKey("document is not a JSON object"))?;
    let fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let required = ["alg", "crv", "kid", "kty", "x", "y"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if fields != required {
        return Err(MinterError::PublicKey(
            "must contain exactly kty, crv, x, y, alg, and kid",
        ));
    }
    let key =
        PublicJwk::parse(text).map_err(|_| MinterError::PublicKey("is not a usable public JWK"))?;
    if key.algorithm().ok() != Some(SigningAlgorithm::Es256)
        || key.kty != "EC"
        || key.crv.as_deref() != Some("P-256")
        || key.alg.as_deref() != Some("ES256")
    {
        return Err(MinterError::PublicKey("must be an ES256 P-256 JWK"));
    }
    let thumbprint = key
        .jkt()
        .map_err(|_| MinterError::PublicKey("thumbprint could not be derived"))?;
    if key.kid.as_deref() != Some(thumbprint.as_str()) || thumbprint.len() != 43 {
        return Err(MinterError::PublicKey(
            "kid must be the RFC 7638 thumbprint",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clients::ClientRegistry;
    use p256::ecdsa::SigningKey as P256SigningKey;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    const NOW: i64 = 1_800_000_000;

    fn client_key(seed: u8, kid: &str) -> (String, Value) {
        let seed_bytes = [seed; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
        let d = URL_SAFE_NO_PAD.encode(seed_bytes);
        let private =
            json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x, "d": d});
        let public = json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x});
        (private.to_string(), public)
    }

    fn p256_key(seed: u8) -> (String, Value) {
        let scalar = [seed; 32];
        let signing = P256SigningKey::from_slice(&scalar).expect("valid P-256 scalar");
        let encoded = signing.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(encoded.x().expect("uncompressed x"));
        let y = URL_SAFE_NO_PAD.encode(encoded.y().expect("uncompressed y"));
        let d = URL_SAFE_NO_PAD.encode(scalar);
        let public_without_kid = PublicJwk::parse(
            &json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "x":x, "y":y}).to_string(),
        )
        .expect("public P-256 JWK parses");
        let kid = public_without_kid.jkt().expect("thumbprint computes");
        let private = json!({
            "kty":"EC", "crv":"P-256", "alg":"ES256", "kid":kid,
            "x":x, "y":y, "d":d
        });
        let public = json!({
            "kty":"EC", "crv":"P-256", "alg":"ES256", "kid":kid,
            "x":x, "y":y
        });
        (private.to_string(), public)
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        minter: TokenMinter,
        registry: ClientRegistry,
    }

    async fn fixture(grant: Option<&str>) -> Fixture {
        build_fixture(grant, "", "").await
    }

    /// `registration` appends lines to the client registration, `claim` appends
    /// lines to the configured claim names. Both are how the delegation tests
    /// reach a shape the plain fixture does not have.
    async fn build_fixture(grant: Option<&str>, registration: &str, claim: &str) -> Fixture {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path();
        fs::create_dir_all(root.join("clients")).expect("client dir");
        fs::create_dir_all(root.join("public-keys")).expect("public key dir");
        fs::create_dir_all(root.join("secrets")).expect("secret dir");

        let (private, public) = p256_key(9);
        let key_path = root.join("secrets/signing.jwk");
        fs::write(&key_path, private).expect("write signing key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let public_file = format!(
            "{}.jwk.json",
            public["kid"].as_str().expect("service key has kid")
        );
        fs::write(
            root.join("public-keys").join(&public_file),
            public.to_string(),
        )
        .expect("write public key");

        let grant_line = grant
            .map(|value| format!("grant: {value}\n"))
            .unwrap_or_default();
        fs::write(
            root.join("clients/client-a.yaml"),
            format!("clientId: client-a\nprincipal: urn:example:client-a\nevidenceAudience: https://client-a.example.org\nrequesterTags: [ministry-of-health, tier-one]\n{grant_line}keys: [{}]\n{registration}", client_key(1, "client-a-1").1),
        )
        .expect("write client");

        let config_path = root.join("mint.yaml");
        let mut document = String::from(
            r#"
version: 1
validationMode: supervised-local-development
issuer: http://127.0.0.1:8081
listener: {address: 127.0.0.1, port: 8081}
signing:
  algorithm: ES256
  activePublicJwkFile: public-keys/PUBLIC
  publishedPublicJwkFiles: []
  revokedKeyIds: []
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing.jwk
secretProviders:
  file: {root: ROOT}
audit:
  path: audit/mint.jsonl
  maximumFileBytes: 1073741824
  hashKeyRef: secret:file/audit-hmac-key
  hashKeyVersion: 1
accessTokens:
  audiences: [evidence]
  lifetimeSeconds: 300
  claims:
    principal: sub
    requesterTags: evidence_tags
    evidenceAudience: evidence_audience
    grantId: evidence_grant_id
    grantAuthority: evidence_authority
"#,
        );
        document.push_str(claim);
        document.push_str(
            r#"clientAssertion:
  audience: http://127.0.0.1:8081/token
  algorithms: [EdDSA]
clients:
  directory: clients
"#,
        );
        document = document
            .replace("ROOT", &root.join("secrets").display().to_string())
            .replace("PUBLIC", &public_file);
        fs::write(&config_path, document).expect("write config");

        let config = MintConfig::load(&config_path).expect("config loads");
        let registry = ClientRegistry::load(&config.clients.directory).expect("registry loads");
        let minter = TokenMinter::new(&config).await.expect("minter builds");
        Fixture {
            _directory: directory,
            minter,
            registry,
        }
    }

    fn write_public_key(directory: &Path, seed: u8) -> std::path::PathBuf {
        let (_private, public) = p256_key(seed);
        let kid = public["kid"].as_str().expect("key has kid");
        let path = directory.join(format!("{kid}.jwk.json"));
        fs::write(&path, public.to_string()).expect("write public key");
        path
    }

    #[test]
    fn published_keys_load_beside_the_active_key() {
        let directory = tempfile::tempdir().expect("temp dir");
        let active = write_public_key(directory.path(), 9);
        let published = write_public_key(directory.path(), 4);
        let mut config = crate::config::tests::sample_config();
        config.signing.active_public_jwk_file = active;
        config.signing.published_public_jwk_files = vec![published];

        let keys = load_public_keys(&config).expect("governed set loads");
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0].kid, keys[1].kid);
    }

    #[test]
    fn a_public_key_may_not_repeat_the_active_key_id() {
        let directory = tempfile::tempdir().expect("temp dir");
        let active = write_public_key(directory.path(), 9);
        let mut config = crate::config::tests::sample_config();
        config.signing.active_public_jwk_file = active.clone();
        config.signing.published_public_jwk_files = vec![active];

        let error = load_public_keys(&config).expect_err("duplicate id is rejected");
        assert!(matches!(error, MinterError::PublicKey(_)), "{error:?}");
    }

    /// Consumers parse the whole set into `JwkSet` before selecting a key, so a
    /// retired entry that is well-formed JSON but not a usable public JWK takes
    /// the whole set down with it: JWKS refresh fails and tokens signed by the
    /// active key start being rejected, while Mint goes on reporting itself
    /// ready. Checking for a `kid` string is not the same as checking the entry
    /// is a key.
    #[test]
    fn an_entry_that_is_not_an_exact_es256_public_key_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("retired.jwk");
        fs::write(&path, r#"{"kid":"mint-2025-07"}"#).expect("write retired key");

        let error = load_public_key(&path).expect_err("an unusable entry is rejected");

        assert!(matches!(error, MinterError::PublicKey(_)), "{error:?}");
    }

    /// RFC 7518 section 6.3.2.7 puts the remaining prime factors of a
    /// multi-prime RSA private key in `oth`. A real private key carries `d` too
    /// and is caught by that, but the published set must not depend on which
    /// private member happens to be present.
    #[test]
    fn a_public_entry_carrying_private_material_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("retired.jwk");
        fs::write(
            &path,
            r#"{"kty":"RSA","kid":"mint-2025-07","n":"sXchDaQ","e":"AQAB","oth":[{"r":"sXchDaQ","d":"sXchDaQ","t":"sXchDaQ"}]}"#,
        )
        .expect("write retired key");

        let error = load_public_key(&path).expect_err("private material is rejected");

        assert!(matches!(error, MinterError::PublicKey(_)), "{error:?}");
    }

    #[test]
    fn revoked_keys_cannot_be_active_or_published() {
        let directory = tempfile::tempdir().expect("temp dir");
        let active = write_public_key(directory.path(), 9);
        let active_key = load_public_key(&active).expect("key loads");
        let mut config = crate::config::tests::sample_config();
        config.signing.active_public_jwk_file = active;
        config.signing.revoked_key_ids = vec![active_key.kid.expect("kid")];

        let error = load_public_keys(&config).expect_err("revoked active key is rejected");
        assert!(matches!(error, MinterError::PublicKey(_)), "{error:?}");
    }

    #[test]
    fn governed_key_ids_and_file_names_are_derived_not_chosen() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (_private, mut public) = p256_key(9);
        public["kid"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let chosen_path = directory
            .path()
            .join("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.jwk.json");
        fs::write(&chosen_path, public.to_string()).expect("write chosen-id key");
        assert!(load_public_key(&chosen_path).is_err());

        let valid_path = write_public_key(directory.path(), 8);
        let wrong_name = directory.path().join("active.jwk.json");
        fs::rename(&valid_path, &wrong_name).expect("rename valid key");
        let mut config = crate::config::tests::sample_config();
        config.signing.active_public_jwk_file = wrong_name;
        assert!(load_public_keys(&config).is_err());
    }

    #[tokio::test]
    async fn local_private_material_must_match_the_governed_active_key() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (private, _) = p256_key(8);
        let secret_path = directory.path().join("mint-signing");
        fs::write(&secret_path, private).expect("write private key");
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let (_, governed_value) = p256_key(9);
        let governed = PublicJwk::parse(&governed_value.to_string()).expect("public JWK parses");
        let mut config = crate::config::tests::sample_config();
        config.validation_mode = crate::config::ValidationMode::SupervisedLocalDevelopment;
        config.signer = SignerConfig::LocalJwk {
            private_key_ref: "secret:file/mint-signing".to_owned(),
        };
        config.secret_providers.file.root = directory.path().to_path_buf();

        assert!(
            build_signer(&config, &governed).await.is_err(),
            "a private key for another public JWK must be rejected"
        );
    }

    fn undelegated(client: &std::sync::Arc<RegisteredClient>) -> AuthenticatedClient {
        AuthenticatedClient {
            client: std::sync::Arc::clone(client),
            delegation: None,
        }
    }

    fn decode_claims(token: &str) -> Value {
        let segment = token.split('.').nth(1).expect("token has a claims segment");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).expect("claims decode"))
            .expect("claims parse")
    }

    fn decode_header(token: &str) -> Value {
        let segment = token.split('.').next().expect("token has a header segment");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).expect("header decode"))
            .expect("header parse")
    }

    #[tokio::test]
    async fn minted_claims_come_from_the_registry() {
        let fixture = fixture(None).await;
        let client = fixture.registry.get("client-a").expect("client registered");
        let minted = fixture
            .minter
            .mint(&undelegated(client), NOW)
            .await
            .expect("token mints");

        let claims = decode_claims(&minted.access_token);
        assert_eq!(claims["iss"], json!("http://127.0.0.1:8081"));
        assert_eq!(claims["aud"], json!("evidence"));
        assert_eq!(claims["sub"], json!("urn:example:client-a"));
        assert_eq!(claims["client_id"], json!("client-a"));
        assert_eq!(
            claims["evidence_tags"],
            json!(["ministry-of-health", "tier-one"])
        );
        assert_eq!(
            claims["evidence_audience"],
            json!("https://client-a.example.org")
        );
        assert_eq!(claims["iat"], json!(NOW));
        assert_eq!(claims["nbf"], json!(NOW));
        assert_eq!(claims["exp"], json!(NOW + 300));
        assert_eq!(minted.expires_in, 300);
        assert_eq!(minted.token_type, "Bearer");
        assert_eq!(minted.scope, None);
        assert!(
            serde_json::to_value(&minted)
                .expect("token response serializes")
                .get("scope")
                .is_none(),
            "Evidence token responses retain their existing shape"
        );
    }

    #[tokio::test]
    async fn scoped_authority_is_minted_from_the_registration_as_standard_claims() {
        let fixture = fixture(None).await;
        let client_path = fixture._directory.path().join("clients/client-a.yaml");
        fs::write(
            &client_path,
            format!(
                "clientId: client-a\nprincipal: urn:example:client-a\nauthorization:\n  scopes: [registry:business:read, registry:business:lookup]\n  claims:\n    purpose: statutory-consultation\n    authority: district-17\nkeys: [{}]\n",
                client_key(1, "client-a-1").1
            ),
        )
        .expect("write scoped client");
        let registry = ClientRegistry::load(
            client_path
                .parent()
                .expect("the registration has a parent directory"),
        )
        .expect("scoped registry loads");
        let client = registry.get("client-a").expect("client registered");

        let minted = fixture
            .minter
            .mint(&undelegated(client), NOW)
            .await
            .expect("token mints");
        let claims = decode_claims(&minted.access_token);

        assert_eq!(
            claims["scope"],
            json!("registry:business:read registry:business:lookup")
        );
        assert_eq!(claims["purpose"], json!("statutory-consultation"));
        assert_eq!(claims["authority"], json!("district-17"));
        assert_eq!(claims["sub"], json!("urn:example:client-a"));
        assert!(claims.get("evidence_tags").is_none());
        assert!(claims.get("evidence_audience").is_none());
        assert_eq!(
            minted.scope.as_deref(),
            Some("registry:business:read registry:business:lookup")
        );
        assert_eq!(
            serde_json::to_value(&minted).expect("token response serializes")["scope"],
            json!("registry:business:read registry:business:lookup")
        );
    }

    #[tokio::test]
    async fn a_listed_authority_claim_is_minted_as_a_json_array() {
        let fixture = fixture(None).await;
        let client_path = fixture._directory.path().join("clients/client-a.yaml");
        fs::write(
            &client_path,
            format!(
                "clientId: client-a\nprincipal: urn:example:client-a\nauthorization:\n  scopes: [registry:business:read]\n  claims:\n    purpose: statutory-consultation\n    authority: [district-17, district-18]\nkeys: [{}]\n",
                client_key(1, "client-a-1").1
            ),
        )
        .expect("write scoped client");
        let registry = ClientRegistry::load(
            client_path
                .parent()
                .expect("the registration has a parent directory"),
        )
        .expect("scoped registry loads");
        let client = registry.get("client-a").expect("client registered");

        let minted = fixture
            .minter
            .mint(&undelegated(client), NOW)
            .await
            .expect("token mints");
        let claims = decode_claims(&minted.access_token);

        assert_eq!(claims["authority"], json!(["district-17", "district-18"]));
        assert_eq!(claims["purpose"], json!("statutory-consultation"));
    }

    #[tokio::test]
    async fn the_header_names_the_active_key_and_access_token_type() {
        let fixture = fixture(None).await;
        let client = fixture.registry.get("client-a").expect("client registered");
        let minted = fixture
            .minter
            .mint(&undelegated(client), NOW)
            .await
            .expect("token mints");

        let header = decode_header(&minted.access_token);
        assert_eq!(header["alg"], json!("ES256"));
        assert_eq!(header["typ"], json!("at+jwt"));
        assert_eq!(
            header["kid"].as_str().map(str::len),
            Some(43),
            "service kid is an RFC 7638 SHA-256 thumbprint"
        );
    }

    #[tokio::test]
    async fn a_grant_is_minted_as_a_matched_pair_or_not_at_all() {
        let without = fixture(None).await;
        let client = without.registry.get("client-a").expect("client registered");
        let claims = decode_claims(
            &without
                .minter
                .mint(&undelegated(client), NOW)
                .await
                .expect("token mints")
                .access_token,
        );
        assert!(claims.get("evidence_grant_id").is_none());
        assert!(claims.get("evidence_authority").is_none());

        let with = fixture(Some("{id: grant-1, authority: statute-7}")).await;
        let client = with.registry.get("client-a").expect("client registered");
        let claims = decode_claims(
            &with
                .minter
                .mint(&undelegated(client), NOW)
                .await
                .expect("token mints")
                .access_token,
        );
        assert_eq!(claims["evidence_grant_id"], json!("grant-1"));
        assert_eq!(claims["evidence_authority"], json!("statute-7"));
    }

    #[tokio::test]
    async fn every_token_carries_a_distinct_identifier() {
        let fixture = fixture(None).await;
        let client = fixture.registry.get("client-a").expect("client registered");
        let first = fixture
            .minter
            .mint(&undelegated(client), NOW)
            .await
            .expect("token mints");
        let second = fixture
            .minter
            .mint(&undelegated(client), NOW)
            .await
            .expect("token mints");

        let first_jti = decode_claims(&first.access_token)["jti"].clone();
        let second_jti = decode_claims(&second.access_token)["jti"].clone();
        assert_ne!(first_jti, second_jti);
    }

    const DELEGATION: &str =
        "delegation:\n  actors: [urn:example:agent-one]\n  subjectClaims:\n    given_name: identity.given_name\n    birth_date: identity.birth_date\n";
    const ACTOR_CLAIM: &str = "    actor: evidence_actor\n";

    async fn delegated_fixture() -> Fixture {
        build_fixture(None, DELEGATION, ACTOR_CLAIM).await
    }

    fn delegation(subject: &[(&str, Value)]) -> crate::assertion::ResolvedDelegation {
        crate::assertion::ResolvedDelegation::new(
            "urn:example:agent-one".to_owned(),
            subject
                .iter()
                .map(|(field, value)| ((*field).to_owned(), value.clone()))
                .collect(),
        )
    }

    fn delegated(
        client: &std::sync::Arc<RegisteredClient>,
        subject: &[(&str, Value)],
    ) -> AuthenticatedClient {
        AuthenticatedClient {
            client: std::sync::Arc::clone(client),
            delegation: Some(delegation(subject)),
        }
    }

    /// The subject is minted at exactly the claim paths the registration
    /// declared, which is what lets a resource server read it back out as the
    /// selector it will not accept from the request body.
    #[tokio::test]
    async fn a_delegated_token_carries_the_actor_and_the_subject_at_their_declared_paths() {
        let fixture = delegated_fixture().await;
        let client = fixture.registry.get("client-a").expect("client registered");
        let minted = fixture
            .minter
            .mint(
                &delegated(
                    client,
                    &[
                        ("given_name", json!("Amara")),
                        ("birth_date", json!("1998-04-02")),
                    ],
                ),
                NOW,
            )
            .await
            .expect("token mints");

        let claims = decode_claims(&minted.access_token);
        assert_eq!(claims["evidence_actor"], json!("urn:example:agent-one"));
        assert_eq!(
            claims["identity"],
            json!({"given_name": "Amara", "birth_date": "1998-04-02"})
        );
        // The registry's own authority is unchanged by the delegation.
        assert_eq!(claims["sub"], json!("urn:example:client-a"));
        assert_eq!(claims["client_id"], json!("client-a"));
    }

    /// An ordinary token from the same minter carries neither, so a resource
    /// server reading the subject from the token has nothing to read.
    #[tokio::test]
    async fn an_undelegated_token_carries_no_actor_and_no_subject() {
        let fixture = delegated_fixture().await;
        let client = fixture.registry.get("client-a").expect("client registered");
        let minted = fixture
            .minter
            .mint(&undelegated(client), NOW)
            .await
            .expect("token mints");

        let claims = decode_claims(&minted.access_token);
        assert!(claims.get("evidence_actor").is_none());
        assert!(claims.get("identity").is_none());
    }

    /// Startup refuses a registry that declares delegation without a configured
    /// actor claim, so this can only be reached by a bug. It must fail rather
    /// than mint a token whose subject no resource server can attribute.
    #[tokio::test]
    async fn minting_a_delegation_without_a_configured_actor_claim_is_a_server_error() {
        let fixture = build_fixture(None, DELEGATION, "").await;
        let client = fixture.registry.get("client-a").expect("client registered");
        let error = fixture
            .minter
            .mint(
                &delegated(
                    client,
                    &[
                        ("given_name", json!("Amara")),
                        ("birth_date", json!("1998-04-02")),
                    ],
                ),
                NOW,
            )
            .await
            .expect_err("an unconfigured actor claim must not mint");
        assert_eq!(
            error,
            TokenError::server_error("no actor claim is configured for delegated tokens")
        );
    }

    #[tokio::test]
    async fn a_delegation_resolved_for_an_undelegated_client_is_a_server_error() {
        let fixture = build_fixture(None, "", ACTOR_CLAIM).await;
        let client = fixture.registry.get("client-a").expect("client registered");
        let error = fixture
            .minter
            .mint(&delegated(client, &[("given_name", json!("Amara"))]), NOW)
            .await
            .expect_err("an undelegated client must not mint a delegation");
        assert_eq!(
            error,
            TokenError::server_error("a delegation was resolved for an undelegated client")
        );
    }

    /// Two fields under one path prefix have to nest into one object rather than
    /// the second overwriting the first.
    #[tokio::test]
    async fn subject_claims_sharing_a_path_prefix_nest_into_one_object() {
        let deep = "delegation:\n  subjectClaims:\n    given_name: subject.identity.given_name\n    region: subject.residence.region\n";
        let fixture = build_fixture(None, deep, ACTOR_CLAIM).await;
        let client = fixture.registry.get("client-a").expect("client registered");
        let minted = fixture
            .minter
            .mint(
                &delegated(
                    client,
                    &[("given_name", json!("Amara")), ("region", json!("north"))],
                ),
                NOW,
            )
            .await
            .expect("token mints");

        assert_eq!(
            decode_claims(&minted.access_token)["subject"],
            json!({"identity": {"given_name": "Amara"}, "residence": {"region": "north"}})
        );
    }

    /// The startup check refuses a subject path rooted at an authority claim, so
    /// this is unreachable in a loaded server. If it were ever reached, the
    /// delegation must not be allowed to overwrite the authority.
    #[tokio::test]
    async fn a_subject_path_colliding_with_an_authority_claim_is_a_server_error() {
        let colliding =
            "delegation:\n  subjectClaims:\n    given_name: evidence_audience.given_name\n";
        let fixture = build_fixture(None, colliding, ACTOR_CLAIM).await;
        let client = fixture.registry.get("client-a").expect("client registered");
        let error = fixture
            .minter
            .mint(&delegated(client, &[("given_name", json!("Amara"))]), NOW)
            .await
            .expect_err("a colliding subject path must not mint");
        assert_eq!(
            error,
            TokenError::server_error("a subject claim path collides with an authority claim")
        );
    }

    #[tokio::test]
    async fn the_published_key_set_carries_public_material_only() {
        let fixture = fixture(None).await;
        let rendered = serde_json::to_string(fixture.minter.jwks()).expect("jwks serializes");
        for member in [
            "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"", "\"k\"",
        ] {
            assert!(
                !rendered.contains(member),
                "the published key set must not contain {member}"
            );
        }
        assert!(rendered.contains("ES256"));
    }

    #[tokio::test]
    async fn debug_output_never_reveals_the_signing_key() {
        let fixture = fixture(None).await;
        let rendered = format!("{:?}", fixture.minter);

        // Useful for operators: which key is live, and under what identity.
        let kid = fixture.minter.signer.key_id();
        assert!(rendered.contains(kid));
        assert!(rendered.contains("http://127.0.0.1:8081"));

        // The private scalar of the fixture's signing key, verbatim. Debug is
        // the easiest place for key material to escape into a log line.
        let private_scalar = URL_SAFE_NO_PAD.encode([9u8; 32]);
        assert!(
            !rendered.contains(&private_scalar),
            "the debug output must never carry private key material"
        );
    }

    struct RecoverableSigner {
        inner: LocalJwkSigner,
        available: AtomicBool,
        ready: AtomicBool,
        attempts: AtomicUsize,
    }

    impl RecoverableSigner {
        fn new() -> Self {
            let (private, _) = p256_key(9);
            let private = PrivateJwk::parse(&private).expect("private JWK parses");
            Self {
                inner: LocalJwkSigner::new(private).expect("test signer builds"),
                available: AtomicBool::new(true),
                ready: AtomicBool::new(true),
                attempts: AtomicUsize::new(0),
            }
        }

        fn set_available(&self, available: bool) {
            self.available.store(available, Ordering::Release);
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::Acquire)
        }
    }

    #[async_trait::async_trait]
    impl SigningProvider for RecoverableSigner {
        fn algorithm(&self) -> SigningAlgorithm {
            self.inner.algorithm()
        }

        fn key_id(&self) -> &str {
            self.inner.key_id()
        }

        fn public_jwk(&self) -> PublicJwk {
            self.inner.public_jwk()
        }

        fn readiness(&self) -> KeyReadiness {
            if self.ready.load(Ordering::Acquire) {
                KeyReadiness::Ready
            } else {
                KeyReadiness::NotReady
            }
        }

        async fn sign(
            &self,
            payload: &[u8],
        ) -> Result<Vec<u8>, registry_platform_crypto::SigningError> {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            if !self.available.load(Ordering::Acquire) {
                self.ready.store(false, Ordering::Release);
                return Err(SigningError::external("provider-token-secret"));
            }
            let result = self.inner.sign(payload).await;
            self.ready.store(result.is_ok(), Ordering::Release);
            result
        }
    }

    #[tokio::test]
    async fn readiness_probes_recover_the_provider_without_exposing_failures() {
        let mut fixture = fixture(None).await;
        let signer = Arc::new(RecoverableSigner::new());
        fixture.minter.signer = signer.clone();
        assert!(fixture.minter.ready().await, "the signer starts ready");
        assert_eq!(signer.attempts(), 0, "a ready signer is not probed");

        let client = fixture.registry.get("client-a").expect("client registered");
        let authenticated = undelegated(client);
        signer.set_available(false);
        let error = fixture
            .minter
            .mint(&authenticated, NOW)
            .await
            .expect_err("provider loss fails the request");
        assert_eq!(signer.readiness(), KeyReadiness::NotReady);
        assert!(
            !format!("{error:?}").contains("provider-token-secret"),
            "provider details must not escape through the request error"
        );
        assert!(
            !fixture.minter.ready().await,
            "a failed recovery probe remains unready"
        );

        signer.set_available(true);
        assert!(
            fixture.minter.ready().await,
            "readiness proves provider recovery without request traffic"
        );
        assert_eq!(signer.readiness(), KeyReadiness::Ready);

        signer.set_available(false);
        fixture
            .minter
            .mint(&authenticated, NOW)
            .await
            .expect_err("a second provider loss fails closed");
        signer.set_available(true);
        fixture
            .minter
            .mint(&authenticated, NOW)
            .await
            .expect("request-path signing also recovers readiness");
        assert_eq!(signer.readiness(), KeyReadiness::Ready);
    }
}
