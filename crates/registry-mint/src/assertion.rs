//! RFC 7523 `private_key_jwt` client authentication.
//!
//! The single most important property in this module is that an assertion is
//! verified against **only the keys registered for the client it claims to be**.
//!
//! The alternative, pooling every client key into one JWK set, is what makes
//! distributing signing keys unsafe: key selection happens by `kid`, which the
//! signer chooses, and nothing downstream re-checks which key was used against
//! the claims that were signed. In a pooled set, client A signs with A's key,
//! writes `iss: client-b`, and verification succeeds. Selecting the key set by
//! the asserted client id *before* verifying removes that move entirely: A's
//! key simply is not in B's set, so the signature fails.
//!
//! Everything else here is bounding: strict structural preflight, an audience
//! bound to this endpoint, a bounded assertion lifetime, and single-use `jti`.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use serde_json::Value;

use crate::{
    clients::{ClientRegistry, RegisteredClient},
    config::ClientAssertionConfig,
    error::TokenError,
    replay::{ReplayCache, ReplayError},
};

/// Bounds chosen so a hostile caller cannot make Mint allocate before any
/// signature has been checked.
const MAX_ASSERTION_BYTES: usize = 16 * 1024;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_CLAIMS_BYTES: usize = 8 * 1024;
const MAX_CLIENT_ID_BYTES: usize = 256;
const MAX_JTI_BYTES: usize = 256;

/// Tolerance for clock difference between a caller and Mint. Applied to the
/// assertion's own `exp` and `nbf`, not to the tokens Mint issues.
const CLOCK_SKEW_SECONDS: i64 = 30;

/// `JWT` is the conventional RFC 7523 assertion type. The explicit type is
/// accepted too, for callers that prefer unambiguous typing.
const ALLOWED_ASSERTION_TYP: [&str; 2] = ["JWT", "client-assertion+jwt"];

/// The parsed but *unverified* surface of an assertion, used only to decide
/// which client's keys to verify against.
struct AssertionPreflight {
    claims: Value,
}

/// Authenticates client assertions against a registry snapshot.
///
/// One verifier is built per registered client at construction time, each bound
/// to that client's own static JWK set.
pub struct ClientAuthenticator {
    registry: Arc<ClientRegistry>,
    verifiers: BTreeMap<String, Arc<TokenVerifier>>,
    maximum_lifetime_seconds: i64,
    replay: Arc<ReplayCache>,
}

impl std::fmt::Debug for ClientAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientAuthenticator")
            .field("clients", &self.verifiers.len())
            .field("maximum_lifetime_seconds", &self.maximum_lifetime_seconds)
            .finish_non_exhaustive()
    }
}

impl ClientAuthenticator {
    /// Build one verifier per registered client.
    ///
    /// The `replay` cache is passed in rather than created here so that
    /// reloading the registry never forgets spent assertion identifiers.
    #[must_use]
    pub fn new(
        registry: Arc<ClientRegistry>,
        config: &ClientAssertionConfig,
        replay: Arc<ReplayCache>,
    ) -> Self {
        let algorithms = config
            .algorithms
            .iter()
            .map(|algorithm| algorithm.as_jsonwebtoken())
            .collect::<Vec<_>>();
        let allowed_typ = ALLOWED_ASSERTION_TYP.map(ToOwned::to_owned).to_vec();

        let mut verifiers = BTreeMap::new();
        for client_id in registry.client_ids() {
            let client = registry
                .get(client_id)
                .expect("client id came from this registry");
            // The static set holds this client's public keys and nothing else.
            let fetcher = Arc::new(JwksFetcher::new_static(
                client.jwks().clone(),
                JwksFetcherConfig::defaults(),
            ));
            let verifier_config = TokenVerifierConfig::access_token_profile(
                // An assertion issues from the client itself.
                client_id.to_owned(),
                vec![config.audience.clone()],
                algorithms.clone(),
                allowed_typ.clone(),
            )
            .with_leeway(Duration::from_secs(CLOCK_SKEW_SECONDS.unsigned_abs()));
            verifiers.insert(
                client_id.to_owned(),
                Arc::new(TokenVerifier::new(verifier_config, fetcher)),
            );
        }

        Self {
            registry,
            verifiers,
            maximum_lifetime_seconds: config.maximum_lifetime_seconds as i64,
            replay,
        }
    }

    #[must_use]
    pub fn registry(&self) -> &Arc<ClientRegistry> {
        &self.registry
    }

    /// Authenticate a client assertion and return the client it proves.
    ///
    /// The returned client is the registry entry, which is where all authority
    /// is read from. Nothing from the assertion payload is carried forward.
    pub async fn authenticate(
        &self,
        assertion: &str,
        now: i64,
    ) -> Result<Arc<RegisteredClient>, TokenError> {
        let preflight = preflight(assertion)?;
        let client_id = asserted_client_id(&preflight.claims)?;

        // Selecting the key set before verifying is the whole point: an
        // unknown client never reaches a signature check, and a known one is
        // checked against its own keys only.
        let client = self
            .registry
            .get(client_id)
            .ok_or_else(|| TokenError::invalid_client("unknown client"))?;
        let verifier = self
            .verifiers
            .get(client_id)
            .ok_or_else(|| TokenError::server_error("registry and verifiers disagree"))?;

        let verified = verifier
            .verify(assertion)
            .await
            .map_err(|_| TokenError::invalid_client("assertion signature or claims rejected"))?;

        // RFC 7523 section 3: for client authentication the subject is the
        // client itself. Without this an assertion could name a different
        // subject while still being signed by a legitimate client key.
        let subject = verified
            .claims
            .sub
            .as_deref()
            .ok_or_else(|| TokenError::invalid_client("assertion has no subject"))?;
        if subject != client_id {
            return Err(TokenError::invalid_client(
                "assertion subject does not match its issuer",
            ));
        }

        let issued_at = verified
            .claims
            .iat
            .ok_or_else(|| TokenError::invalid_client("assertion has no issued-at"))?;
        let expires_at = verified
            .claims
            .exp
            .ok_or_else(|| TokenError::invalid_client("assertion has no expiry"))?;
        // A long-lived assertion is a long-lived bearer credential. Bound it
        // regardless of what the caller chose.
        if expires_at <= issued_at
            || expires_at.saturating_sub(issued_at) > self.maximum_lifetime_seconds
        {
            return Err(TokenError::invalid_client(
                "assertion lifetime exceeds the configured maximum",
            ));
        }
        // The verifier also checks expiry, but against its own read of the
        // system clock. Freshness, the replay window, and the audit record must
        // agree on one instant, so they are all decided against `now`.
        if expires_at.saturating_add(CLOCK_SKEW_SECONDS) <= now {
            return Err(TokenError::invalid_client("assertion has expired"));
        }
        if issued_at.saturating_sub(CLOCK_SKEW_SECONDS) > now {
            return Err(TokenError::invalid_client("assertion is not yet issued"));
        }

        let jti = verified
            .claims
            .extra
            .get("jti")
            .and_then(Value::as_str)
            .ok_or_else(|| TokenError::invalid_client("assertion has no jti"))?;
        if jti.is_empty() || jti.len() > MAX_JTI_BYTES {
            return Err(TokenError::invalid_client("assertion jti is not bounded"));
        }
        // Namespaced by client so two clients choosing the same jti do not
        // lock each other out.
        let replay_key = format!("{client_id}\u{0}{jti}");
        // Remembered past `exp` by the same skew the freshness check tolerates.
        // Forgetting it at `exp` would leave a window in which the assertion is
        // still accepted but no longer recorded as spent.
        self.replay
            .remember(
                &replay_key,
                expires_at.saturating_add(CLOCK_SKEW_SECONDS),
                now,
            )
            .map_err(|error| match error {
                ReplayError::AlreadyUsed => TokenError::invalid_client("assertion already used"),
                ReplayError::Saturated => TokenError::server_error("replay cache saturated"),
                ReplayError::Poisoned => TokenError::server_error("replay cache poisoned"),
            })?;

        Ok(Arc::clone(client))
    }
}

/// Structural validation performed before any allocation-heavy or
/// cryptographic work, mirroring the strictness Evidence applies to bearer
/// tokens.
fn preflight(assertion: &str) -> Result<AssertionPreflight, TokenError> {
    let malformed = || TokenError::invalid_client("assertion is malformed");

    if assertion.is_empty() || assertion.len() > MAX_ASSERTION_BYTES {
        return Err(malformed());
    }
    let segments = assertion.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(malformed());
    }

    let header = decode_segment(segments[0], MAX_HEADER_BYTES)?;
    if !header.is_object() {
        return Err(malformed());
    }
    let claims = decode_segment(segments[1], MAX_CLAIMS_BYTES)?;
    if !claims.is_object() {
        return Err(malformed());
    }
    // A present but undecodable or empty signature is malformed regardless of
    // what the verifier would later say about it.
    let signature = URL_SAFE_NO_PAD
        .decode(segments[2])
        .map_err(|_| malformed())?;
    if signature.is_empty() {
        return Err(malformed());
    }

    Ok(AssertionPreflight { claims })
}

/// Decode one base64url segment into strictly parsed JSON.
///
/// `parse_json_strict` rejects duplicate members, so a header or claim set that
/// says one thing to a lenient parser and another to a strict one cannot get
/// past this point.
fn decode_segment(segment: &str, maximum_bytes: usize) -> Result<Value, TokenError> {
    let malformed = || TokenError::invalid_client("assertion is malformed");
    if segment.len() > maximum_bytes {
        return Err(malformed());
    }
    let bytes = URL_SAFE_NO_PAD.decode(segment).map_err(|_| malformed())?;
    if bytes.len() > maximum_bytes {
        return Err(malformed());
    }
    parse_json_strict(&bytes).map_err(|_| malformed())
}

fn asserted_client_id(claims: &Value) -> Result<&str, TokenError> {
    let issuer = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| TokenError::invalid_client("assertion has no issuer"))?;
    if issuer.is_empty() || issuer.len() > MAX_CLIENT_ID_BYTES {
        return Err(TokenError::invalid_client(
            "assertion issuer is not bounded",
        ));
    }
    Ok(issuer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Algorithm;
    use serde_json::json;

    // Deterministic per-seed Ed25519 keys so tests can hold several distinct
    // client identities at once.
    pub(crate) fn test_key(seed: u8) -> (registry_platform_crypto::PrivateJwk, Value) {
        let seed_bytes = [seed; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
        let d = URL_SAFE_NO_PAD.encode(seed_bytes);
        let kid = format!("key-{seed}");
        let private = registry_platform_crypto::PrivateJwk::parse(
            &json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x, "d": d})
                .to_string(),
        )
        .expect("test private JWK parses");
        let public = json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x});
        (private, public)
    }

    fn sign_assertion(
        private: &registry_platform_crypto::PrivateJwk,
        typ: &str,
        claims: &Value,
    ) -> String {
        let kid = private.kid.clone().expect("test key has a kid");
        let header = json!({"alg": "EdDSA", "typ": typ, "kid": kid});
        let encode = |value: &Value| {
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("value serializes"))
        };
        let signing_input = format!("{}.{}", encode(&header), encode(claims));
        let signature = registry_platform_crypto::sign(signing_input.as_bytes(), private)
            .expect("test key signs");
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    const AUDIENCE: &str = "https://mint.example.org/token";
    const NOW: i64 = 1_800_000_000;

    fn assertion_claims(client_id: &str, jti: &str) -> Value {
        json!({
            "iss": client_id,
            "sub": client_id,
            "aud": AUDIENCE,
            "iat": NOW,
            "exp": NOW + 120,
            "jti": jti,
        })
    }

    fn registry_with(clients: &[(&str, &Value)]) -> Arc<ClientRegistry> {
        let directory = tempfile::tempdir().expect("temp dir");
        for (client_id, public) in clients {
            let document = format!(
                "clientId: {client_id}\nprincipal: urn:example:{client_id}\nevidenceAudience: https://{client_id}.example.org\nrequesterTags: [tag-{client_id}]\nkeys: [{public}]\n"
            );
            std::fs::write(directory.path().join(format!("{client_id}.yaml")), document)
                .expect("write client registration");
        }
        Arc::new(ClientRegistry::load(directory.path()).expect("registry loads"))
    }

    fn authenticator(registry: Arc<ClientRegistry>) -> ClientAuthenticator {
        let config = ClientAssertionConfig {
            audience: AUDIENCE.to_owned(),
            maximum_lifetime_seconds: 300,
            algorithms: vec![Algorithm::EdDSA],
            replay_cache_entries: 256,
        };
        ClientAuthenticator::new(registry, &config, Arc::new(ReplayCache::new(256)))
    }

    #[tokio::test]
    async fn a_valid_assertion_authenticates_its_client() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));
        let assertion = sign_assertion(&private, "JWT", &assertion_claims("client-a", "jti-1"));

        let client = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect("valid assertion authenticates");
        assert_eq!(client.client_id(), "client-a");
        assert_eq!(client.principal(), "urn:example:client-a");
    }

    /// The core security property. Client A holds a real, registered key. It
    /// cannot use that key to speak as client B.
    #[tokio::test]
    async fn one_clients_key_cannot_sign_an_assertion_for_another_client() {
        let (private_a, public_a) = test_key(1);
        let (_private_b, public_b) = test_key(2);
        let authenticator = authenticator(registry_with(&[
            ("client-a", &public_a),
            ("client-b", &public_b),
        ]));

        // A signs an assertion that claims to be B.
        let forged = sign_assertion(&private_a, "JWT", &assertion_claims("client-b", "jti-1"));

        let error = authenticator
            .authenticate(&forged, NOW)
            .await
            .expect_err("a forged assertion must be rejected");
        assert_eq!(
            error,
            TokenError::invalid_client("assertion signature or claims rejected")
        );
    }

    /// Even naming its own kid does not help: the kid is looked up inside the
    /// asserted client's key set, where A's key does not exist.
    #[tokio::test]
    async fn naming_a_foreign_kid_does_not_reach_another_clients_key_set() {
        let (private_a, public_a) = test_key(1);
        let (_private_b, public_b) = test_key(2);
        let authenticator = authenticator(registry_with(&[
            ("client-a", &public_a),
            ("client-b", &public_b),
        ]));

        let mut claims = assertion_claims("client-b", "jti-1");
        claims["sub"] = json!("client-b");
        let forged = sign_assertion(&private_a, "JWT", &claims);
        assert!(authenticator.authenticate(&forged, NOW).await.is_err());
    }

    #[tokio::test]
    async fn an_unknown_client_is_rejected_before_any_signature_check() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));
        let assertion = sign_assertion(&private, "JWT", &assertion_claims("client-z", "jti-1"));

        let error = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect_err("unknown clients are rejected");
        assert_eq!(error, TokenError::invalid_client("unknown client"));
    }

    #[tokio::test]
    async fn the_subject_must_equal_the_issuer() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));
        let mut claims = assertion_claims("client-a", "jti-1");
        claims["sub"] = json!("someone-else");
        let assertion = sign_assertion(&private, "JWT", &claims);

        let error = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect_err("a mismatched subject is rejected");
        assert_eq!(
            error,
            TokenError::invalid_client("assertion subject does not match its issuer")
        );
    }

    #[tokio::test]
    async fn an_assertion_is_single_use() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));
        let assertion = sign_assertion(&private, "JWT", &assertion_claims("client-a", "jti-1"));

        assert!(authenticator.authenticate(&assertion, NOW).await.is_ok());
        let error = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect_err("a replayed assertion is rejected");
        assert_eq!(error, TokenError::invalid_client("assertion already used"));
    }

    /// Freshness tolerates clock skew, so an assertion stays acceptable for a
    /// short window past its own `exp`. The replay record has to outlive that
    /// window: if it expired first, a captured assertion would become
    /// replayable exactly as it was about to stop being useful.
    #[tokio::test]
    async fn an_assertion_stays_single_use_for_as_long_as_it_stays_acceptable() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));
        let assertion = sign_assertion(&private, "JWT", &assertion_claims("client-a", "jti-1"));

        assert!(authenticator.authenticate(&assertion, NOW).await.is_ok());

        // One second past `exp`, still inside the accepted skew window.
        let error = authenticator
            .authenticate(&assertion, NOW + 121)
            .await
            .expect_err("a replayed assertion is rejected while it is still accepted");
        assert_eq!(error, TokenError::invalid_client("assertion already used"));

        // Past the window the assertion is refused on freshness instead, so the
        // replay record has no further work to do.
        let error = authenticator
            .authenticate(&assertion, NOW + 151)
            .await
            .expect_err("an assertion past the skew window is refused");
        assert_eq!(error, TokenError::invalid_client("assertion has expired"));
    }

    #[tokio::test]
    async fn two_clients_may_use_the_same_jti_value() {
        let (private_a, public_a) = test_key(1);
        let (private_b, public_b) = test_key(2);
        let authenticator = authenticator(registry_with(&[
            ("client-a", &public_a),
            ("client-b", &public_b),
        ]));

        let from_a = sign_assertion(&private_a, "JWT", &assertion_claims("client-a", "shared"));
        let from_b = sign_assertion(&private_b, "JWT", &assertion_claims("client-b", "shared"));
        assert!(authenticator.authenticate(&from_a, NOW).await.is_ok());
        assert!(authenticator.authenticate(&from_b, NOW).await.is_ok());
    }

    #[tokio::test]
    async fn an_assertion_for_another_audience_is_rejected() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));
        let mut claims = assertion_claims("client-a", "jti-1");
        claims["aud"] = json!("https://another-service.example.org/token");
        let assertion = sign_assertion(&private, "JWT", &claims);

        assert!(authenticator.authenticate(&assertion, NOW).await.is_err());
    }

    #[tokio::test]
    async fn expired_and_over_long_assertions_are_rejected() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));

        let mut expired = assertion_claims("client-a", "jti-1");
        expired["iat"] = json!(NOW - 400);
        expired["exp"] = json!(NOW - 300);
        let assertion = sign_assertion(&private, "JWT", &expired);
        assert_eq!(
            authenticator
                .authenticate(&assertion, NOW)
                .await
                .expect_err("an expired assertion is rejected"),
            TokenError::invalid_client("assertion has expired")
        );

        let mut ahead = assertion_claims("client-a", "jti-3");
        ahead["iat"] = json!(NOW + 400);
        ahead["exp"] = json!(NOW + 500);
        let assertion = sign_assertion(&private, "JWT", &ahead);
        assert_eq!(
            authenticator
                .authenticate(&assertion, NOW)
                .await
                .expect_err("an assertion issued in the future is rejected"),
            TokenError::invalid_client("assertion is not yet issued")
        );

        let mut over_long = assertion_claims("client-a", "jti-2");
        over_long["exp"] = json!(NOW + 4_000);
        let assertion = sign_assertion(&private, "JWT", &over_long);
        let error = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect_err("an over-long assertion is rejected");
        assert_eq!(
            error,
            TokenError::invalid_client("assertion lifetime exceeds the configured maximum")
        );
    }

    #[tokio::test]
    async fn an_assertion_without_a_jti_is_rejected() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));
        let mut claims = assertion_claims("client-a", "jti-1");
        claims.as_object_mut().expect("claims object").remove("jti");
        let assertion = sign_assertion(&private, "JWT", &claims);

        let error = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect_err("a jti is required");
        assert_eq!(error, TokenError::invalid_client("assertion has no jti"));
    }

    #[tokio::test]
    async fn an_unsigned_or_malformed_assertion_never_reaches_the_registry() {
        let authenticator = authenticator(registry_with(&[("client-a", &test_key(1).1)]));
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT","kid":"key-1"}"#);
        let claims = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&assertion_claims("client-a", "jti-1")).expect("claims"));

        for candidate in [
            String::new(),
            "not-a-jwt".to_owned(),
            "a.b".to_owned(),
            "a.b.c.d".to_owned(),
            format!("{header}.{claims}."),
            format!("{header}..x"),
            format!("{header}.{claims}.!!!"),
        ] {
            let error = authenticator
                .authenticate(&candidate, NOW)
                .await
                .expect_err("malformed assertions are rejected");
            assert_eq!(error, TokenError::invalid_client("assertion is malformed"));
        }
    }

    #[tokio::test]
    async fn duplicate_json_members_are_rejected_by_the_strict_preflight() {
        let (private, _public) = test_key(1);
        let public = test_key(1).1;
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));

        // Two `iss` members: a lenient parser would take one, a strict parser
        // refuses to guess.
        let raw_claims = format!(
            r#"{{"iss":"client-a","iss":"client-b","sub":"client-a","aud":"{AUDIENCE}","iat":{NOW},"exp":{},"jti":"jti-1"}}"#,
            NOW + 120
        );
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT","kid":"key-1"}"#);
        let claims = URL_SAFE_NO_PAD.encode(raw_claims.as_bytes());
        let signing_input = format!("{header}.{claims}");
        let signature = registry_platform_crypto::sign(signing_input.as_bytes(), &private)
            .expect("test key signs");
        let assertion = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));

        let error = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect_err("duplicate members are rejected");
        assert_eq!(error, TokenError::invalid_client("assertion is malformed"));
    }

    #[tokio::test]
    async fn an_access_token_type_is_not_accepted_as_a_client_assertion() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));
        let assertion = sign_assertion(&private, "at+jwt", &assertion_claims("client-a", "jti-1"));

        assert!(authenticator.authenticate(&assertion, NOW).await.is_err());
    }
}
