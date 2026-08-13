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
    clients::{ClientRegistry, Delegation, RegisteredClient},
    config::ClientAssertionConfig,
    error::TokenError,
    replay::{ReplayCache, ReplayError},
    ON_BEHALF_OF_CLAIM,
};

/// Bounds chosen so a hostile caller cannot make Mint allocate before any
/// signature has been checked.
const MAX_ASSERTION_BYTES: usize = 16 * 1024;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_CLAIMS_BYTES: usize = 8 * 1024;
const MAX_CLIENT_ID_BYTES: usize = 256;
const MAX_JTI_BYTES: usize = 256;
/// Evidence rejects an actor longer than this, and a selector value longer than
/// this could not satisfy any selector profile.
const MAX_DELEGATION_VALUE_BYTES: usize = 512;

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

/// A delegation request that the registry permits, ready to be minted.
///
/// Every value here came from the signed assertion and was then checked against
/// the client's registration: the actor against its permitted set, and the
/// subject against the exact selector fields it declared. Nothing unbounded or
/// undeclared survives into this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedDelegation {
    actor: String,
    /// Selector field to its value, keyed exactly as the registration declared.
    subject: BTreeMap<String, Value>,
}

impl ResolvedDelegation {
    /// Crate-internal because the type's meaning is that its contents already
    /// passed [`build_delegation`]; nothing outside this crate may assert one.
    pub(crate) fn new(actor: String, subject: BTreeMap<String, Value>) -> Self {
        Self { actor, subject }
    }

    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    #[must_use]
    pub fn subject(&self) -> &BTreeMap<String, Value> {
        &self.subject
    }
}

/// An authenticated client, and the delegation it authenticated for.
#[derive(Clone, Debug)]
pub struct AuthenticatedClient {
    pub client: Arc<RegisteredClient>,
    pub delegation: Option<ResolvedDelegation>,
}

/// Authenticates registered client credentials against a registry snapshot.
///
/// One verifier is built per `private_key_jwt` client at construction time,
/// each bound to that client's own static JWK set. Client-secret registrations
/// carry no key set and take the constant-time fingerprint path instead.
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
            .field("clients", &self.registry.len())
            .field("private_key_jwt_clients", &self.verifiers.len())
            .field("maximum_lifetime_seconds", &self.maximum_lifetime_seconds)
            .finish_non_exhaustive()
    }
}

impl ClientAuthenticator {
    /// Build one verifier per registered `private_key_jwt` client.
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
            if !client.accepts_private_key_jwt() {
                continue;
            }
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
    /// is read from. The one thing carried forward from the assertion payload
    /// is the delegation request, and only after the registry has confirmed
    /// that this client may delegate, to that actor, over exactly those subject
    /// fields.
    pub async fn authenticate(
        &self,
        assertion: &str,
        now: i64,
    ) -> Result<AuthenticatedClient, TokenError> {
        let preflight = preflight(assertion)?;
        let client_id = asserted_client_id(&preflight.claims)?;

        // Selecting the key set before verifying is the whole point: an
        // unknown client never reaches a signature check, and a known one is
        // checked against its own keys only.
        let client = self
            .registry
            .get(client_id)
            .ok_or_else(|| TokenError::invalid_client("unknown client"))?;
        if !client.accepts_private_key_jwt() {
            return Err(TokenError::invalid_client(
                "client authentication method does not match its registration",
            ));
        }
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

        // Resolved before the assertion is spent so a rejected delegation does
        // not burn the caller's jti.
        let delegation = resolve_delegation(client, &verified.claims.extra)?;

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

        Ok(AuthenticatedClient {
            client: Arc::clone(client),
            delegation,
        })
    }

    /// Authenticate a bounded client id and high-entropy secret.
    ///
    /// Secret-authenticated registrations are standard-authority only, so no
    /// request-carried delegation can survive this authentication method.
    pub fn authenticate_client_secret(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<AuthenticatedClient, TokenError> {
        let client = self
            .registry
            .get(client_id)
            .ok_or_else(|| TokenError::invalid_client("unknown client"))?;
        if client.accepts_private_key_jwt() {
            return Err(TokenError::invalid_client(
                "client authentication method does not match its registration",
            ));
        }
        if !client.verifies_client_secret(client_secret) {
            return Err(TokenError::invalid_client("client secret was rejected"));
        }
        Ok(AuthenticatedClient {
            client: Arc::clone(client),
            delegation: None,
        })
    }
}

/// Reconcile the delegation the assertion asks for with the one the registry
/// permits.
///
/// Both directions fail closed. A client with no registered delegation cannot
/// obtain an actor or a bound subject by asking for one, and a client that *is*
/// registered for delegation cannot obtain an ordinary unbounded token by
/// omitting the request. The second half is what stops a delegated caller
/// quietly widening its own reach.
fn resolve_delegation(
    client: &RegisteredClient,
    claims: &serde_json::Map<String, Value>,
) -> Result<Option<ResolvedDelegation>, TokenError> {
    let requested = claims.get(ON_BEHALF_OF_CLAIM);
    match (client.delegation(), requested) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(TokenError::invalid_client(
            "client is not registered to act on behalf of a subject",
        )),
        (Some(_), None) => Err(TokenError::invalid_client(
            "a delegated client must name the actor and subject it acts for",
        )),
        (Some(registered), Some(requested)) => Ok(Some(build_delegation(registered, requested)?)),
    }
}

fn build_delegation(
    registered: &Delegation,
    requested: &Value,
) -> Result<ResolvedDelegation, TokenError> {
    let invalid = |reason: &'static str| TokenError::invalid_client(reason);

    let requested = requested
        .as_object()
        .ok_or_else(|| invalid("the delegation request is malformed"))?;
    // An unrecognized member would be silently dropped, leaving the caller
    // believing it constrained something it did not.
    if requested.len() != 2 || !requested.contains_key("actor") {
        return Err(invalid("the delegation request is malformed"));
    }

    let actor = requested
        .get("actor")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("the delegation request is malformed"))?;
    if actor.trim().is_empty() || actor.len() > MAX_DELEGATION_VALUE_BYTES {
        return Err(invalid("the delegated actor is not bounded"));
    }
    if !registered.permits_actor(actor) {
        return Err(invalid("the client may not act as this actor"));
    }

    let subject = requested
        .get("subject")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("the delegation request is malformed"))?;
    // Exactly the declared fields: a missing one would leave the resource
    // server unable to resolve the subject, and an extra one would be minted
    // nowhere while looking to the caller as though it had been honoured.
    if subject.len() != registered.subject_claims.len() {
        return Err(invalid(
            "the delegated subject does not match its registration",
        ));
    }
    let mut resolved = BTreeMap::new();
    for field in registered.subject_claims.keys() {
        let value = subject
            .get(field)
            .ok_or_else(|| invalid("the delegated subject does not match its registration"))?;
        resolved.insert(field.clone(), bounded_selector_value(value)?);
    }

    Ok(ResolvedDelegation::new(actor.to_owned(), resolved))
}

/// The value shapes a resource server can read back out as a selector value.
fn bounded_selector_value(value: &Value) -> Result<Value, TokenError> {
    match value {
        Value::String(text) if !text.is_empty() && text.len() <= MAX_DELEGATION_VALUE_BYTES => {
            Ok(value.clone())
        }
        Value::Bool(_) => Ok(value.clone()),
        // Only integers survive a JSON round trip into a selector value.
        Value::Number(number) if number.is_i64() => Ok(value.clone()),
        _ => Err(TokenError::invalid_client(
            "a delegated subject value is not a bounded string, integer, or boolean",
        )),
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
pub(crate) mod tests {
    use super::*;
    use crate::config::Algorithm;
    use registry_platform_authcommon::fingerprint_api_key;
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
        registry_of(
            &clients
                .iter()
                .map(|(id, key)| (*id, *key, ""))
                .collect::<Vec<_>>(),
        )
    }

    /// Each entry is a client id, its public key, and any extra registration
    /// lines (a `delegation:` block, in these tests).
    fn registry_of(clients: &[(&str, &Value, &str)]) -> Arc<ClientRegistry> {
        let directory = tempfile::tempdir().expect("temp dir");
        for (client_id, public, extra) in clients {
            let document = format!(
                "clientId: {client_id}\nprincipal: urn:example:{client_id}\nevidenceAudience: https://{client_id}.example.org\nrequesterTags: [tag-{client_id}]\nkeys: [{public}]\n{extra}"
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

    fn secret_registry(client_id: &str, secret: &str) -> Arc<ClientRegistry> {
        let directory = tempfile::tempdir().expect("temp dir");
        let fingerprint = fingerprint_api_key(secret);
        let document = format!(
            "clientId: {client_id}\nprincipal: urn:example:{client_id}\nauthorization: {{scopes: [registry:read]}}\nclientAuthentication:\n  method: client-secret\n  secretFingerprints: [{fingerprint}]\n"
        );
        std::fs::write(directory.path().join("client.yaml"), document)
            .expect("write client registration");
        Arc::new(ClientRegistry::load(directory.path()).expect("registry loads"))
    }

    #[tokio::test]
    async fn a_valid_assertion_authenticates_its_client() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));
        let assertion = sign_assertion(&private, "JWT", &assertion_claims("client-a", "jti-1"));

        let authenticated = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect("valid assertion authenticates");
        assert_eq!(authenticated.client.client_id(), "client-a");
        assert_eq!(authenticated.client.principal(), "urn:example:client-a");
        assert_eq!(authenticated.delegation, None);
    }

    #[test]
    fn a_valid_client_secret_authenticates_only_its_registered_client() {
        let authenticator = authenticator(secret_registry(
            "qgis-installation",
            "correct-high-entropy-client-secret-value",
        ));

        let authenticated = authenticator
            .authenticate_client_secret(
                "qgis-installation",
                "correct-high-entropy-client-secret-value",
            )
            .expect("valid secret authenticates");
        assert_eq!(authenticated.client.client_id(), "qgis-installation");
        assert_eq!(authenticated.delegation, None);

        for (client_id, secret) in [
            ("qgis-installation", "wrong-client-secret"),
            (
                "unknown-installation",
                "correct-high-entropy-client-secret-value",
            ),
        ] {
            assert_eq!(
                authenticator
                    .authenticate_client_secret(client_id, secret)
                    .expect_err("an invalid credential is rejected")
                    .code(),
                crate::error::TokenErrorCode::InvalidClient
            );
        }
    }

    #[tokio::test]
    async fn a_client_cannot_switch_its_registered_authentication_method() {
        let (private, public) = test_key(1);
        let private_key_authenticator = authenticator(registry_with(&[("client-a", &public)]));
        assert_eq!(
            private_key_authenticator
                .authenticate_client_secret("client-a", "any-secret")
                .expect_err("a key client cannot authenticate with a secret"),
            TokenError::invalid_client(
                "client authentication method does not match its registration"
            )
        );

        let secret_authenticator = authenticator(secret_registry(
            "client-a",
            "correct-high-entropy-client-secret-value",
        ));
        let assertion = sign_assertion(&private, "JWT", &assertion_claims("client-a", "jti-1"));
        assert_eq!(
            secret_authenticator
                .authenticate(&assertion, NOW)
                .await
                .expect_err("a secret client cannot authenticate with an assertion"),
            TokenError::invalid_client(
                "client authentication method does not match its registration"
            )
        );
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

    const DELEGATION: &str = "delegation:\n  actors: [urn:example:agent-one, urn:example:agent-two]\n  subjectClaims:\n    given_name: identity.given_name\n    birth_date: identity.birth_date\n";

    fn on_behalf_of(jti: &str, request: Value) -> Value {
        let mut claims = assertion_claims("client-a", jti);
        claims[ON_BEHALF_OF_CLAIM] = request;
        claims
    }

    fn subject_request() -> Value {
        json!({
            "actor": "urn:example:agent-one",
            "subject": {"given_name": "Amara", "birth_date": "1998-04-02"},
        })
    }

    /// A delegated assertion carries the actor and the subject; both survive
    /// only because the registration named them.
    #[tokio::test]
    async fn a_delegated_assertion_resolves_the_actor_and_subject_it_names() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_of(&[("client-a", &public, DELEGATION)]));
        let assertion = sign_assertion(&private, "JWT", &on_behalf_of("jti-1", subject_request()));

        let authenticated = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect("a permitted delegation authenticates");
        let delegation = authenticated.delegation.expect("delegation resolved");
        assert_eq!(delegation.actor(), "urn:example:agent-one");
        assert_eq!(
            delegation.subject(),
            &BTreeMap::from([
                ("birth_date".to_owned(), json!("1998-04-02")),
                ("given_name".to_owned(), json!("Amara")),
            ])
        );
    }

    /// Asking is not enough. Delegation is a property of the registration.
    #[tokio::test]
    async fn a_client_with_no_registered_delegation_cannot_ask_for_one() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));
        let assertion = sign_assertion(&private, "JWT", &on_behalf_of("jti-1", subject_request()));

        let error = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect_err("an undelegated client is refused");
        assert_eq!(
            error,
            TokenError::invalid_client("client is not registered to act on behalf of a subject")
        );
    }

    /// The other direction, and the one that is easy to miss: if omitting the
    /// request produced an ordinary token, a delegated caller could widen its
    /// own reach from one subject to every subject by leaving out a claim.
    #[tokio::test]
    async fn a_delegated_client_cannot_widen_itself_by_omitting_the_request() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_of(&[("client-a", &public, DELEGATION)]));
        let assertion = sign_assertion(&private, "JWT", &assertion_claims("client-a", "jti-1"));

        let error = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect_err("a delegated client must name its subject");
        assert_eq!(
            error,
            TokenError::invalid_client(
                "a delegated client must name the actor and subject it acts for"
            )
        );
    }

    #[tokio::test]
    async fn an_actor_outside_the_registered_set_is_refused() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_of(&[("client-a", &public, DELEGATION)]));
        let mut request = subject_request();
        request["actor"] = json!("urn:example:agent-three");
        let assertion = sign_assertion(&private, "JWT", &on_behalf_of("jti-1", request));

        let error = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect_err("an unregistered actor is refused");
        assert_eq!(
            error,
            TokenError::invalid_client("the client may not act as this actor")
        );
    }

    /// Without an `actors` list the client names its own actor, so the actor is
    /// an audit label rather than a bound. The subject binding is unaffected.
    #[tokio::test]
    async fn an_open_actor_list_still_binds_the_subject() {
        let (private, public) = test_key(1);
        let open = "delegation:\n  subjectClaims:\n    given_name: identity.given_name\n    birth_date: identity.birth_date\n";
        let authenticator = authenticator(registry_of(&[("client-a", &public, open)]));
        let mut request = subject_request();
        request["actor"] = json!("urn:example:anything");
        let assertion = sign_assertion(&private, "JWT", &on_behalf_of("jti-1", request));

        let authenticated = authenticator
            .authenticate(&assertion, NOW)
            .await
            .expect("any actor is permitted");
        let delegation = authenticated.delegation.expect("delegation resolved");
        assert_eq!(delegation.actor(), "urn:example:anything");
        assert_eq!(delegation.subject().len(), 2);
    }

    /// A missing field would leave the resource server unable to resolve the
    /// subject; an extra one would be minted nowhere while looking to the caller
    /// as though it had been honoured.
    #[tokio::test]
    async fn the_subject_must_carry_exactly_the_registered_fields() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_of(&[("client-a", &public, DELEGATION)]));

        let mut missing = subject_request();
        missing["subject"] = json!({"given_name": "Amara"});
        let mut extra = subject_request();
        extra["subject"] = json!({
            "given_name": "Amara",
            "birth_date": "1998-04-02",
            "national_id": "some-identifier",
        });
        let mut renamed = subject_request();
        renamed["subject"] = json!({"given_name": "Amara", "family_name": "Okafor"});

        for (index, request) in [missing, extra, renamed].into_iter().enumerate() {
            let assertion = sign_assertion(
                &private,
                "JWT",
                &on_behalf_of(&format!("jti-{index}"), request),
            );
            let error = authenticator
                .authenticate(&assertion, NOW)
                .await
                .expect_err("a mismatched subject is refused");
            assert_eq!(
                error,
                TokenError::invalid_client("the delegated subject does not match its registration")
            );
        }
    }

    /// Only the shapes a resource server can read back out as a selector value.
    #[tokio::test]
    async fn a_subject_value_that_is_not_a_selector_value_is_refused() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_of(&[("client-a", &public, DELEGATION)]));

        for (index, value) in [
            json!(null),
            json!(""),
            json!(1.5),
            json!(["Amara"]),
            json!({"value": "Amara"}),
            json!("x".repeat(513)),
        ]
        .into_iter()
        .enumerate()
        {
            let mut request = subject_request();
            request["subject"] = json!({"given_name": value, "birth_date": "1998-04-02"});
            let assertion = sign_assertion(
                &private,
                "JWT",
                &on_behalf_of(&format!("jti-{index}"), request),
            );
            let error = authenticator
                .authenticate(&assertion, NOW)
                .await
                .expect_err("an unusable subject value is refused");
            assert_eq!(
                error,
                TokenError::invalid_client(
                    "a delegated subject value is not a bounded string, integer, or boolean"
                )
            );
        }

        // Integers and booleans are selector values, so they are accepted.
        let mut numeric = subject_request();
        numeric["subject"] = json!({"given_name": 42, "birth_date": true});
        let assertion = sign_assertion(&private, "JWT", &on_behalf_of("jti-ok", numeric));
        assert!(authenticator.authenticate(&assertion, NOW).await.is_ok());
    }

    /// A malformed request must not cost the caller its `jti`: the delegation is
    /// reconciled before the assertion is spent, so correcting the request and
    /// retrying works.
    #[tokio::test]
    async fn a_refused_delegation_does_not_spend_the_assertion() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_of(&[("client-a", &public, DELEGATION)]));

        let mut wrong = subject_request();
        wrong["actor"] = json!("urn:example:agent-three");
        let refused = sign_assertion(&private, "JWT", &on_behalf_of("jti-1", wrong));
        assert!(authenticator.authenticate(&refused, NOW).await.is_err());

        // Same jti, corrected request.
        let corrected = sign_assertion(&private, "JWT", &on_behalf_of("jti-1", subject_request()));
        assert!(authenticator.authenticate(&corrected, NOW).await.is_ok());
    }

    #[tokio::test]
    async fn a_structurally_malformed_delegation_request_is_refused() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_of(&[("client-a", &public, DELEGATION)]));

        let mut unknown_member = subject_request();
        unknown_member["scope"] = json!("everything");
        let mut no_subject = subject_request();
        no_subject
            .as_object_mut()
            .expect("request object")
            .remove("subject");

        for (index, request) in [
            json!("urn:example:agent-one"),
            json!([{"actor": "urn:example:agent-one"}]),
            json!({"subject": {"given_name": "Amara", "birth_date": "1998-04-02"}}),
            json!({"actor": "urn:example:agent-one", "subject": "Amara"}),
            unknown_member,
            no_subject,
        ]
        .into_iter()
        .enumerate()
        {
            let assertion = sign_assertion(
                &private,
                "JWT",
                &on_behalf_of(&format!("jti-{index}"), request),
            );
            let error = authenticator
                .authenticate(&assertion, NOW)
                .await
                .expect_err("a malformed delegation request is refused");
            assert_eq!(
                error,
                TokenError::invalid_client("the delegation request is malformed")
            );
        }

        let mut blank_actor = subject_request();
        blank_actor["actor"] = json!("   ");
        let assertion = sign_assertion(&private, "JWT", &on_behalf_of("jti-blank", blank_actor));
        assert_eq!(
            authenticator
                .authenticate(&assertion, NOW)
                .await
                .expect_err("a blank actor is refused"),
            TokenError::invalid_client("the delegated actor is not bounded")
        );
    }

    #[tokio::test]
    async fn an_access_token_type_is_not_accepted_as_a_client_assertion() {
        let (private, public) = test_key(1);
        let authenticator = authenticator(registry_with(&[("client-a", &public)]));
        let assertion = sign_assertion(&private, "at+jwt", &assertion_claims("client-a", "jti-1"));

        assert!(authenticator.authenticate(&assertion, NOW).await.is_err());
    }
}
