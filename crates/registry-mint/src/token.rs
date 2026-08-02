//! Access token minting.
//!
//! Every authority claim written here is read from the server-side client
//! registry. Nothing is copied from the client assertion. That is what makes a
//! caller's private key a proof of *identity* rather than a licence to assert
//! whatever it likes: the caller chooses which registry entry it authenticates
//! as, and the registry chooses what that entry may say.

use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};
use serde::Serialize;
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::{
    clients::{contains_private_material, RegisteredClient},
    config::{Algorithm, ClaimNames, MintConfig},
    error::TokenError,
    secretfile::{self, SecretFileError},
    ACCESS_TOKEN_TYP,
};

#[derive(Debug, Error)]
pub enum MinterError {
    #[error("the signing key file could not be read: {0}")]
    SigningKeyFile(#[from] SecretFileError),
    #[error("the signing key is invalid: {0}")]
    SigningKey(&'static str),
    #[error("a retired public key is invalid: {0}")]
    RetiredKey(&'static str),
}

/// A minted access token and the lifetime the caller should assume.
#[derive(Debug, Serialize)]
pub struct MintedToken {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
}

/// Signs access tokens with the configured active key.
pub struct TokenMinter {
    issuer: String,
    audience: Value,
    lifetime_seconds: i64,
    claims: ClaimNames,
    algorithm: Algorithm,
    signer: LocalJwkSigner,
    jwks: Value,
}

impl std::fmt::Debug for TokenMinter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenMinter")
            .field("issuer", &self.issuer)
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.signer.key_id())
            .finish_non_exhaustive()
    }
}

impl TokenMinter {
    /// Load the active signing key and build the published JWK set.
    pub fn new(config: &MintConfig) -> Result<Self, MinterError> {
        let key_text = secretfile::read_owner_only(&config.signing.active_key_file)?;
        let private = PrivateJwk::parse(&key_text)
            .map_err(|_| MinterError::SigningKey("not a private JWK"))?;

        // A mismatch here would publish one key id and sign with another, so
        // verifiers would fail to find the key that actually signed.
        if private.kid.as_deref() != Some(config.signing.active_key_id.as_str()) {
            return Err(MinterError::SigningKey(
                "key id does not match the configured active key id",
            ));
        }
        let signer =
            LocalJwkSigner::new(private).map_err(|_| MinterError::SigningKey("is not usable"))?;
        if signer.public_jwk().alg.as_deref() != Some(config.signing.algorithm.as_header_value()) {
            return Err(MinterError::SigningKey(
                "algorithm does not match the configured signing algorithm",
            ));
        }

        let jwks = build_jwks(&signer, &config.signing.retired_public_jwk_files)?;

        let audience = if config.access_tokens.audiences.len() == 1 {
            Value::String(config.access_tokens.audiences[0].clone())
        } else {
            Value::Array(
                config
                    .access_tokens
                    .audiences
                    .iter()
                    .map(|audience| Value::String(audience.clone()))
                    .collect(),
            )
        };

        Ok(Self {
            issuer: config.issuer.clone(),
            audience,
            lifetime_seconds: config.access_tokens.lifetime_seconds as i64,
            claims: config.access_tokens.claims.clone(),
            algorithm: config.signing.algorithm,
            signer,
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

    /// Mint an access token carrying the registry's authority for `client`.
    pub async fn mint(
        &self,
        client: &RegisteredClient,
        now: i64,
    ) -> Result<MintedToken, TokenError> {
        let expires_at = now + self.lifetime_seconds;
        let mut claims = Map::new();
        claims.insert("iss".to_owned(), Value::String(self.issuer.clone()));
        claims.insert("aud".to_owned(), self.audience.clone());
        claims.insert("iat".to_owned(), json!(now));
        claims.insert("nbf".to_owned(), json!(now));
        claims.insert("exp".to_owned(), json!(expires_at));
        claims.insert(
            "jti".to_owned(),
            Value::String(ulid::Ulid::new().to_string()),
        );
        // `client_id` records which registration authenticated; the principal
        // is what the resource server acts on. They are allowed to differ.
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
        claims.insert(
            self.claims.principal.clone(),
            Value::String(client.principal().to_owned()),
        );
        claims.insert(
            self.claims.requester_tags.clone(),
            Value::Array(
                client
                    .requester_tags()
                    .iter()
                    .map(|tag| Value::String(tag.clone()))
                    .collect(),
            ),
        );
        claims.insert(
            self.claims.evidence_audience.clone(),
            Value::String(client.evidence_audience().to_owned()),
        );
        // Evidence requires the grant id and authority together or not at all,
        // which the registry already guarantees by construction.
        if let Some(grant) = client.grant() {
            claims.insert(
                self.claims.grant_id.clone(),
                Value::String(grant.id.clone()),
            );
            claims.insert(
                self.claims.grant_authority.clone(),
                Value::String(grant.authority.clone()),
            );
        }

        let header = json!({
            "alg": self.algorithm.as_header_value(),
            "typ": ACCESS_TOKEN_TYP,
            "kid": self.signer.key_id(),
        });
        let signing_input = format!(
            "{}.{}",
            encode_json(&header)?,
            encode_json(&Value::Object(claims))?
        );
        let signature = self
            .signer
            .sign(signing_input.as_bytes())
            .await
            .map_err(|_| TokenError::server_error("the access token could not be signed"))?;

        Ok(MintedToken {
            access_token: format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)),
            token_type: "Bearer",
            expires_in: self.lifetime_seconds as u64,
        })
    }
}

fn encode_json(value: &Value) -> Result<String, TokenError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| TokenError::server_error("a token component could not be serialized"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Publish the active public key plus any retired public keys whose tokens may
/// still be in flight.
fn build_jwks(
    signer: &LocalJwkSigner,
    retired: &[std::path::PathBuf],
) -> Result<Value, MinterError> {
    let active = serde_json::to_value(signer.public_jwk())
        .map_err(|_| MinterError::SigningKey("public key could not be serialized"))?;
    let mut keys = vec![active];
    for path in retired {
        keys.push(load_retired_public_key(path)?);
    }
    Ok(json!({ "keys": keys }))
}

fn load_retired_public_key(path: &Path) -> Result<Value, MinterError> {
    let text =
        std::fs::read_to_string(path).map_err(|_| MinterError::RetiredKey("is unreadable"))?;
    let value: Value =
        serde_json::from_str(&text).map_err(|_| MinterError::RetiredKey("is not JSON"))?;
    let object = value
        .as_object()
        .ok_or(MinterError::RetiredKey("is not a JSON object"))?;
    // The whole point of the published set is that it is public.
    if contains_private_material(object) {
        return Err(MinterError::RetiredKey("contains private key material"));
    }
    if !object.get("kid").is_some_and(Value::is_string) {
        return Err(MinterError::RetiredKey("has no key id"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clients::ClientRegistry;
    use std::{fs, os::unix::fs::PermissionsExt};

    const NOW: i64 = 1_800_000_000;

    fn ed25519_key(seed: u8, kid: &str) -> (String, Value) {
        let seed_bytes = [seed; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
        let d = URL_SAFE_NO_PAD.encode(seed_bytes);
        let private =
            json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x, "d": d});
        let public = json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x});
        (private.to_string(), public)
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        minter: TokenMinter,
        registry: ClientRegistry,
    }

    fn fixture(grant: Option<&str>) -> Fixture {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path();
        fs::create_dir_all(root.join("clients")).expect("client dir");

        let (private, _public) = ed25519_key(9, "mint-2026-01");
        let key_path = root.join("signing.jwk");
        fs::write(&key_path, private).expect("write signing key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("chmod");

        let grant_line = grant
            .map(|value| format!("grant: {value}\n"))
            .unwrap_or_default();
        fs::write(
            root.join("clients/client-a.yaml"),
            format!("clientId: client-a\nprincipal: urn:example:client-a\nevidenceAudience: https://client-a.example.org\nrequesterTags: [ministry-of-health, tier-one]\n{grant_line}keys: [{}]\n", ed25519_key(1, "client-a-1").1),
        )
        .expect("write client");

        let config_path = root.join("mint.yaml");
        fs::write(
            &config_path,
            r#"
version: 1
issuer: https://mint.example.org
listener: {address: 127.0.0.1, port: 8081}
signing:
  algorithm: EdDSA
  activeKeyId: mint-2026-01
  activeKeyFile: signing.jwk
accessTokens:
  audiences: [evidence]
  lifetimeSeconds: 300
  claims:
    principal: sub
    requesterTags: evidence_tags
    evidenceAudience: evidence_audience
    grantId: evidence_grant_id
    grantAuthority: evidence_authority
clientAssertion:
  audience: https://mint.example.org/token
  algorithms: [EdDSA]
clients:
  directory: clients
"#,
        )
        .expect("write config");

        let config = MintConfig::load(&config_path).expect("config loads");
        let registry = ClientRegistry::load(&config.clients.directory).expect("registry loads");
        let minter = TokenMinter::new(&config).expect("minter builds");
        Fixture {
            _directory: directory,
            minter,
            registry,
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
        let fixture = fixture(None);
        let client = fixture.registry.get("client-a").expect("client registered");
        let minted = fixture.minter.mint(client, NOW).await.expect("token mints");

        let claims = decode_claims(&minted.access_token);
        assert_eq!(claims["iss"], json!("https://mint.example.org"));
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
    }

    #[tokio::test]
    async fn the_header_names_the_active_key_and_access_token_type() {
        let fixture = fixture(None);
        let client = fixture.registry.get("client-a").expect("client registered");
        let minted = fixture.minter.mint(client, NOW).await.expect("token mints");

        assert_eq!(
            decode_header(&minted.access_token),
            json!({"alg": "EdDSA", "typ": "at+jwt", "kid": "mint-2026-01"})
        );
    }

    #[tokio::test]
    async fn a_grant_is_minted_as_a_matched_pair_or_not_at_all() {
        let without = fixture(None);
        let client = without.registry.get("client-a").expect("client registered");
        let claims = decode_claims(
            &without
                .minter
                .mint(client, NOW)
                .await
                .expect("token mints")
                .access_token,
        );
        assert!(claims.get("evidence_grant_id").is_none());
        assert!(claims.get("evidence_authority").is_none());

        let with = fixture(Some("{id: grant-1, authority: statute-7}"));
        let client = with.registry.get("client-a").expect("client registered");
        let claims = decode_claims(
            &with
                .minter
                .mint(client, NOW)
                .await
                .expect("token mints")
                .access_token,
        );
        assert_eq!(claims["evidence_grant_id"], json!("grant-1"));
        assert_eq!(claims["evidence_authority"], json!("statute-7"));
    }

    #[tokio::test]
    async fn every_token_carries_a_distinct_identifier() {
        let fixture = fixture(None);
        let client = fixture.registry.get("client-a").expect("client registered");
        let first = fixture.minter.mint(client, NOW).await.expect("token mints");
        let second = fixture.minter.mint(client, NOW).await.expect("token mints");

        let first_jti = decode_claims(&first.access_token)["jti"].clone();
        let second_jti = decode_claims(&second.access_token)["jti"].clone();
        assert_ne!(first_jti, second_jti);
    }

    #[test]
    fn the_published_key_set_carries_public_material_only() {
        let fixture = fixture(None);
        let rendered = serde_json::to_string(fixture.minter.jwks()).expect("jwks serializes");
        for member in [
            "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"", "\"k\"",
        ] {
            assert!(
                !rendered.contains(member),
                "the published key set must not contain {member}"
            );
        }
        assert!(rendered.contains("mint-2026-01"));
    }

    #[test]
    fn debug_output_never_reveals_the_signing_key() {
        let fixture = fixture(None);
        let rendered = format!("{:?}", fixture.minter);

        // Useful for operators: which key is live, and under what identity.
        assert!(rendered.contains("mint-2026-01"));
        assert!(rendered.contains("https://mint.example.org"));

        // The private scalar of the fixture's signing key, verbatim. Debug is
        // the easiest place for key material to escape into a log line.
        let private_scalar = URL_SAFE_NO_PAD.encode([9u8; 32]);
        assert!(
            !rendered.contains(&private_scalar),
            "the debug output must never carry private key material"
        );
    }
}
