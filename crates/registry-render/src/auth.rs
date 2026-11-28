//! Bearer verification belongs only to the HTTP adapter.
use crate::problem::{ProblemKind, RenderProblem};
use crate::runtime::{IssuerRuntime, RenderRuntime};
use registry_platform_authcommon::FailedCheck;
use registry_platform_config::{Admitted, CallerIssuerEntry, ClientRule};
use registry_platform_oidc::{
    fetch_discovery_for_issuer, AccessTokenAlgorithm, CallerRefusal, ClaimNames, DeclaredKinds,
    IssuerEntry, IssuerNetworkPolicy, IssuerSet, IssuerSetError, JwksFetcher, JwksFetcherConfig,
    OidcDiscoveryConfig, OidcError, TokenVerifier, TokenVerifierConfig,
};
use registry_platform_yaml::LocalId;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// The access-token signature algorithms the service accepts.
const ACCEPTED_ALGORITHMS: [AccessTokenAlgorithm; 2] =
    [AccessTokenAlgorithm::RS256, AccessTokenAlgorithm::ES256];

fn accepted_algorithms() -> Vec<jsonwebtoken::Algorithm> {
    ACCEPTED_ALGORITHMS
        .into_iter()
        .map(AccessTokenAlgorithm::to_jsonwebtoken)
        .collect()
}

/// The verifier of one issuer entry: its keys, token type, scope claim and
/// clients, with the entry's assertion issuers.
async fn entry_verifier(
    runtime: &RenderRuntime,
    id: &LocalId,
    entry: &IssuerRuntime,
) -> Result<TokenVerifier, RenderProblem> {
    let id = id.as_str();
    let refuse = || {
        RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!("authentication.oidc.issuers.{id} signing keys could not be loaded; check the issuer and configured JWKS source"),
        )
    };
    let core = entry.core();
    let provider = &core.provider;
    let network = IssuerNetworkPolicy::new(provider.issuer.as_str(), provider.allow_insecure_http)
        .map_err(|_| refuse())?;
    let keys = match &provider.jwks_source {
        registry_platform_config::JwksSource::Discovery {} => {
            let (discovery, policy) = fetch_discovery_for_issuer(
                &OidcDiscoveryConfig {
                    issuer: provider.issuer.to_string(),
                    jwks_uri_override: None,
                    discovery_timeout: Duration::from_secs(5),
                    max_doc_bytes: 1024 * 1024,
                },
                provider.allow_insecure_http,
            )
            .await
            .map_err(|_| refuse())?;
            JwksFetcher::new_with_fetch_url_policy(
                discovery.jwks_uri,
                JwksFetcherConfig::defaults(),
                policy,
            )
        }
        registry_platform_config::JwksSource::Uri { uri } => {
            JwksFetcher::new_with_fetch_url_policy(
                uri.to_string(),
                JwksFetcherConfig::defaults(),
                network.declared_jwks_fetch_policy(),
            )
        }
        registry_platform_config::JwksSource::Static { document_ref }
        | registry_platform_config::JwksSource::TestIssuer { document_ref } => {
            let bytes = crate::runtime::resolve_secret(runtime, document_ref)?;
            let keys =
                registry_platform_oidc::parse_static_jwks(&bytes).map_err(|error| match error {
                    OidcError::StaticKeySet(refused) => RenderProblem::new(
                        ProblemKind::RuntimeInvalid,
                        format!(
                            "authentication.oidc.issuers.{id}.jwksSource.documentRef was refused: {refused}"
                        ),
                    ),
                    _ => refuse(),
                })?;
            JwksFetcher::new_static(keys, JwksFetcherConfig::defaults())
        }
    };
    let profile = TokenVerifierConfig::for_caller_issuer(core, accepted_algorithms(), None)
        .map_err(|_| refuse())?
        .with_assertion_issuers(entry.assertion_issuers.clone());
    Ok(TokenVerifier::new(profile, Arc::new(keys)))
}

/// The issuers the service accepts Render credentials from, and the scope
/// each route requires.
pub(crate) struct Callers {
    issuers: IssuerSet,
    render_scope: String,
    seal_scope: String,
    /// The claim each entry reads its scopes from, by issuer id.
    scope_claims: BTreeMap<String, String>,
    /// The issuer id of the entry that lists a client. A client belongs to
    /// that one issuer: a token another issuer signs never carries it.
    client_issuers: BTreeMap<String, String>,
}

/// The two routes that take an OIDC credential, each with its own scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// The render and document routes.
    Render,
    /// The seal route.
    Seal,
}

impl Callers {
    pub(crate) fn new(
        entries: Vec<IssuerEntry>,
        scope_claims: BTreeMap<String, String>,
        client_issuers: BTreeMap<String, String>,
        render_scope: String,
        seal_scope: String,
    ) -> Result<Self, RenderProblem> {
        let issuers = IssuerSet::new(entries, ClaimNames::default()).map_err(|error| {
            RenderProblem::new(
                ProblemKind::RuntimeInvalid,
                match error {
                    IssuerSetError::Empty => {
                        "authentication.oidc.issuers lists no issuer".to_owned()
                    }
                    IssuerSetError::DuplicateIss { first, second } => {
                        format!("authentication.oidc.issuers.{second} names the issuer of {first}")
                    }
                    IssuerSetError::InvalidClaimNames => {
                        "the caller claim names are invalid".to_owned()
                    }
                },
            )
        })?;
        if let Some(entry) = issuers
            .entries()
            .find(|entry| !scope_claims.contains_key(&*entry.id))
        {
            return Err(RenderProblem::new(
                ProblemKind::RuntimeInvalid,
                format!(
                    "authentication.oidc.issuers.{} has no scope claim",
                    entry.id
                ),
            ));
        }
        Ok(Self {
            issuers,
            render_scope,
            seal_scope,
            scope_claims,
            client_issuers,
        })
    }

    /// The scope `route` requires.
    pub(crate) fn scope(&self, route: Route) -> &str {
        match route {
            Route::Render => &self.render_scope,
            Route::Seal => &self.seal_scope,
        }
    }

    /// Whether every issuer's key source can answer.
    pub(crate) async fn keys_ready(&self) -> bool {
        for entry in self.issuers.entries() {
            if entry
                .verifier()
                .key_source()
                .ensure_key_set()
                .await
                .is_err()
            {
                return false;
            }
        }
        true
    }

    /// Verify `token` with the issuer entry its `iss` names and require the
    /// scope `route` needs.
    pub(crate) async fn authenticate(
        &self,
        token: &str,
        route: Route,
    ) -> Result<Authenticated, AuthenticationError> {
        registry_platform_authcommon::validate_compact_access_token(token)
            .map_err(|_| AuthenticationError::refused(FailedCheck::CredentialMalformed))?;
        let caller = self.issuers.verify(token).await.map_err(verifier_failure)?;
        // The entry's verifier owns resource membership and the configured
        // client binding. Unrelated task-grant claims confer no Render
        // authority.
        let caller_fingerprint = registry_platform_authcommon::fingerprint_api_key(token);
        let verified = &caller.token;
        if !verified
            .scopes
            .iter()
            .any(|scope| scope == self.scope(route))
        {
            return Err(AuthenticationError::Forbidden {
                caller_fingerprint,
                check: FailedCheck::Scope,
                scope_claim: self
                    .scope_claims
                    .get(&*caller.issuer_id)
                    .cloned()
                    .unwrap_or_default(),
            });
        }
        // With an allowlist the verifier has bound the client and records which
        // claim matched. Without one, the signed claims name it, in the same
        // order the verifier would read them: `azp`, then `client_id`.
        let named = match verified.matched_client_id() {
            Ok(Some(client)) => Some(client.to_owned()),
            Ok(None) => verified
                .claims
                .azp
                .clone()
                .or_else(|| verified.claims.client_id.clone())
                .filter(|client| !client.is_empty()),
            Err(_) => return Err(AuthenticationError::refused(FailedCheck::TokenClient)),
        };
        // A client another issuer lists is not this issuer's to name.
        let client_id = named.filter(|client| {
            self.client_issuers
                .get(client)
                .is_none_or(|owner| owner.as_str() == &*caller.issuer_id)
        });
        // Correlate the exact verified credential, as in legacy API-key mode.
        // Issuer, subject, and client claims are never written into the audit event.
        Ok(Authenticated {
            caller_fingerprint,
            client_id,
        })
    }
}

/// The callers of a runtime that configures OIDC authentication. `None` for
/// the legacy API key.
pub(crate) async fn callers(runtime: &RenderRuntime) -> Result<Option<Callers>, RenderProblem> {
    let Some(oidc) = &runtime.authentication.oidc else {
        return Ok(None);
    };
    let mut entries = Vec::new();
    let mut scope_claims = BTreeMap::new();
    let mut client_issuers = BTreeMap::new();
    for (id, entry) in oidc.issuers.iter() {
        let core = entry.core();
        let declared = DeclaredKinds::from_core(core).map_err(|_| {
            RenderProblem::new(
                ProblemKind::RuntimeInvalid,
                format!(
                    "authentication.oidc.issuers.{} declares actorKind and clientActorKinds together",
                    id.as_str()
                ),
            )
        })?;
        let verifier = entry_verifier(runtime, id, entry).await?;
        entries.push(IssuerEntry::new(id.as_str(), verifier, declared));
        scope_claims.insert(
            id.as_str().to_owned(),
            core.scope_claim.get().as_str().to_owned(),
        );
        if let Admitted::Listed(listed) = core.allowed_clients.admitted() {
            for client in listed {
                client_issuers.insert(client.clone(), id.as_str().to_owned());
            }
        }
    }
    Callers::new(
        entries,
        scope_claims,
        client_issuers,
        oidc.render_scope().as_str().to_owned(),
        oidc.seal_scope().as_str().to_owned(),
    )
    .map(Some)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AuthenticationError {
    /// The credential was refused, by the check that refused it. The remedy
    /// names the setting that changes the answer, for the log line only.
    Refused {
        check: FailedCheck,
        remedy: Option<&'static str>,
    },
    Forbidden {
        caller_fingerprint: String,
        check: FailedCheck,
        /// The claim the verifying entry reads scopes from.
        scope_claim: String,
    },
    Unavailable,
}

impl AuthenticationError {
    fn refused(check: FailedCheck) -> Self {
        Self::Refused {
            check,
            remedy: None,
        }
    }

    /// A refusal that names only the check, as the credential checks of the
    /// HTTP layer make.
    pub(crate) fn refused_by(check: FailedCheck) -> Self {
        Self::refused(check)
    }

    /// The check that refused the caller. A key source that cannot answer is
    /// the verifier's own outage.
    #[deny(clippy::wildcard_enum_match_arm)]
    pub(crate) fn failed_check(&self) -> FailedCheck {
        match self {
            Self::Refused { check, .. } | Self::Forbidden { check, .. } => *check,
            Self::Unavailable => FailedCheck::KeySourceUnavailable,
        }
    }
}

fn verifier_failure(refusal: CallerRefusal) -> AuthenticationError {
    if refusal.error.is_key_source_unavailable() {
        AuthenticationError::Unavailable
    } else {
        AuthenticationError::Refused {
            check: refusal.failed_check(),
            remedy: refusal.remedy,
        }
    }
}

/// A verified Render resource credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Authenticated {
    /// The fingerprint of the exact credential, the only caller value the
    /// audit records.
    pub(crate) caller_fingerprint: String,
    /// The verified client, compared against a seal's `allowedClients` and
    /// never audited. `None` when the token names no client, or names one
    /// that another issuer lists.
    pub(crate) client_id: Option<String>,
}

#[cfg(test)]
mod token_characterisation;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::runtime::{DEFAULT_RENDER_SCOPE, DEFAULT_SEAL_SCOPE};
    use base64::Engine as _;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
    use registry_platform_oidc::{ActorKind, CallerKind};
    use serde_json::{json, Value};
    pub(crate) const CANARY_KEY: &[u8] = b"canary-render-signing-key-01234567890123456789";
    #[test]
    fn the_service_accepts_exactly_rs256_and_es256_access_tokens() {
        assert_eq!(
            accepted_algorithms(),
            vec![Algorithm::RS256, Algorithm::ES256]
        );
    }
    pub(crate) fn test_jwks() -> Value {
        json!({"keys":[{"kty":"oct","kid":"canary","alg":"HS256","use":"sig","k":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(CANARY_KEY)}]})
    }

    /// One HS256 issuer entry named `id`, over `keys`, that lists `clients`
    /// (every client when empty).
    fn hs256_entry(
        id: &str,
        issuer: &str,
        clients: &[&str],
        keys: Arc<JwksFetcher>,
    ) -> IssuerEntry {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Doc {
            entry: Entry,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Entry {
            #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer-core"))]
            core: registry_platform_config::CallerIssuerCore<
                registry_platform_config::AllowedClients,
            >,
        }
        let allowed = if clients.is_empty() {
            "unrestricted".to_owned()
        } else {
            format!("[{}]", clients.join(", "))
        };
        let text = format!(
            "apiVersion: registry.registrystack.org/example-runtime/v1alpha1\nkind: ExampleRuntimeConfig\nentry:\n  issuer: {issuer}\n  audience: urn:render:test\n  allowedClients: {allowed}\n"
        );
        let core = registry_platform_config::RuntimeConfigLoader::new_without_posture(
            registry_platform_config::RuntimeEnvelope {
                api_version: "registry.registrystack.org/example-runtime/v1alpha1",
                kind: "ExampleRuntimeConfig",
            },
        )
        .parse_str::<Doc>(&text, |_| None)
        .unwrap_or_else(|error| panic!("loads: {:?}", error.diagnostics()))
        .config
        .entry
        .core;
        let profile = TokenVerifierConfig::for_caller_issuer(&core, vec![Algorithm::HS256], None)
            .expect("a listed or unrestricted entry resolves")
            .with_leeway(Duration::ZERO);
        IssuerEntry::new(id, TokenVerifier::new(profile, keys), DeclaredKinds::None)
    }

    fn static_keys() -> Arc<JwksFetcher> {
        Arc::new(JwksFetcher::new_static(
            serde_json::from_value(test_jwks()).unwrap(),
            JwksFetcherConfig::defaults(),
        ))
    }

    /// The callers of one HS256 issuer, `https://issuer.example.test`, that
    /// lists the client `portal`.
    pub(crate) fn test_callers() -> Callers {
        test_callers_over(static_keys())
    }

    pub(crate) fn test_callers_over(keys: Arc<JwksFetcher>) -> Callers {
        callers_of(vec![hs256_entry(
            "test",
            "https://issuer.example.test",
            &["portal"],
            keys,
        )])
    }

    /// The callers of the HS256 entries given, with the default scopes.
    pub(crate) fn callers_of(entries: Vec<IssuerEntry>) -> Callers {
        let scope_claims = entries
            .iter()
            .map(|entry| (entry.id.to_string(), "scope".to_owned()))
            .collect();
        Callers::new(
            entries,
            scope_claims,
            BTreeMap::new(),
            DEFAULT_RENDER_SCOPE.to_owned(),
            DEFAULT_SEAL_SCOPE.to_owned(),
        )
        .expect("test callers")
    }

    pub(crate) fn token(overrides: Value) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({"iss":"https://issuer.example.test","sub":"canary-principal","aud":"urn:render:test","iat":now,"exp":now+300,"client_id":"portal","scope":"render:render"});
        claims
            .as_object_mut()
            .unwrap()
            .extend(overrides.as_object().unwrap().clone());
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("canary".to_owned());
        header.typ = Some("at+jwt".to_owned());
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(CANARY_KEY)).unwrap()
    }
    #[tokio::test]
    async fn accepted_resource_membership_ignores_unrelated_grants() {
        let callers = test_callers();
        let credential = token(
            json!({"aud":["urn:other","urn:render:test"],"registry_grant_id":"canary-unrelated"}),
        );
        let caller = callers
            .authenticate(&credential, Route::Render)
            .await
            .expect("independently authorized Render token");
        assert_eq!(
            caller.caller_fingerprint,
            registry_platform_authcommon::fingerprint_api_key(&credential)
        );
    }

    #[tokio::test]
    async fn caller_correlates_the_verified_credential_not_principal_claims() {
        let callers = test_callers();
        let first = token(json!({"jti":"canary-first"}));
        let second = token(json!({"jti":"canary-second"}));
        let caller = callers
            .authenticate(&first, Route::Render)
            .await
            .unwrap()
            .caller_fingerprint;
        assert_eq!(
            caller,
            registry_platform_authcommon::fingerprint_api_key(&first)
        );
        let again = callers.authenticate(&first, Route::Render).await.unwrap();
        assert_eq!(again.caller_fingerprint, caller);
        let other = callers.authenticate(&second, Route::Render).await.unwrap();
        assert_ne!(other.caller_fingerprint, caller);
    }

    #[tokio::test]
    async fn resource_expiry_signature_scope_and_grant_boundaries() {
        let callers = test_callers();
        let caller = callers
            .authenticate(&token(json!({})), Route::Render)
            .await
            .expect("valid Render resource token");
        assert!(!caller.caller_fingerprint.contains("canary-principal"));
        for overrides in [
            json!({"aud":"urn:other"}),
            json!({"exp":1}),
            json!({"scope":"other"}),
            json!({"client_id":"other"}),
        ] {
            assert!(callers
                .authenticate(&token(overrides), Route::Render)
                .await
                .is_err());
        }
        assert!(callers
            .authenticate("canary-invalid-token", Route::Render)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn each_route_scope_authorizes_only_its_own_route() {
        let callers = test_callers();
        let render_only = token(json!({"scope":"render:render"}));
        let seal_only = token(json!({"scope":"render:seal"}));
        let both = token(json!({"scope":"render:render render:seal"}));
        assert!(matches!(
            callers.authenticate(&render_only, Route::Seal).await,
            Err(AuthenticationError::Forbidden { .. })
        ));
        assert!(matches!(
            callers.authenticate(&seal_only, Route::Render).await,
            Err(AuthenticationError::Forbidden { .. })
        ));
        assert!(callers.authenticate(&seal_only, Route::Seal).await.is_ok());
        assert!(callers.authenticate(&both, Route::Seal).await.is_ok());
        assert!(callers.authenticate(&both, Route::Render).await.is_ok());
    }

    #[tokio::test]
    async fn the_verified_client_is_returned_for_the_seal_allowlist() {
        let bound = test_callers()
            .authenticate(&token(json!({})), Route::Render)
            .await
            .unwrap();
        assert_eq!(bound.client_id.as_deref(), Some("portal"));
        let unrestricted = callers_of(vec![hs256_entry(
            "test",
            "https://issuer.example.test",
            &[],
            static_keys(),
        )]);
        for (claims, client) in [
            (json!({"client_id":"records"}), Some("records")),
            (
                json!({"client_id":"records","azp":"records"}),
                Some("records"),
            ),
            (json!({"client_id":null}), None),
        ] {
            let verified = unrestricted
                .authenticate(&token(claims), Route::Render)
                .await
                .unwrap();
            assert_eq!(verified.client_id.as_deref(), client);
        }
    }

    /// A deployment over static key sets: the runtime file, its key files,
    /// and one ES256 key per issuer name.
    pub(crate) struct Deployment {
        _scratch: tempfile::TempDir,
        home: std::path::PathBuf,
        keys: BTreeMap<&'static str, PrivateJwk>,
    }

    impl Deployment {
        /// A home with a key file `jwks-<name>.json` for each issuer name.
        pub(crate) fn new(names: &[&'static str]) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let scratch = tempfile::tempdir().expect("home directory");
            let home = scratch
                .path()
                .canonicalize()
                .expect("physical home directory");
            std::fs::create_dir(home.join("bundle")).expect("package directory");
            std::fs::create_dir(home.join("audit")).expect("audit directory");
            let mut keys = BTreeMap::new();
            for name in names {
                let key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("ES256 key");
                let file = home.join(format!("jwks-{name}.json"));
                std::fs::write(&file, json!({"keys":[key.public()]}).to_string())
                    .expect("write the key set");
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
                    .expect("owner-only key file");
                keys.insert(*name, key);
            }
            Self {
                _scratch: scratch,
                home,
                keys,
            }
        }

        /// An issuer entry of the `issuers` map: `issuer` is the entry's
        /// issuer URL, `members` its other members, one per line at the
        /// entry's depth.
        pub(crate) fn entry(&self, name: &str, issuer: &str, members: &str) -> String {
            format!(
                "      {name}:\n        issuer: {issuer}\n        audience: urn:render:test\n        jwksSource:\n          type: static\n          documentRef: secret:file/jwks-{name}.json\n{members}"
            )
        }

        /// The callers of a runtime whose `oidc` block is `issuers`, with
        /// `siblings` written beside it.
        pub(crate) async fn callers(
            &self,
            issuers: &str,
            siblings: &str,
        ) -> Result<Option<Callers>, RenderProblem> {
            self.callers_under(crate::runtime::DEFAULT_POSTURE, issuers, siblings)
                .await
        }

        /// [`Self::callers`], loading the runtime file under `declared`.
        pub(crate) async fn callers_under(
            &self,
            declared: registry_platform_config::DeclaredPosture,
            issuers: &str,
            siblings: &str,
        ) -> Result<Option<Callers>, RenderProblem> {
            let runtime = format!(
                "apiVersion: {}\nkind: {}\nlistener:\n  bind: 127.0.0.1:18080\npackage:\n  root: {}\nsecretProviders:\n  file:\n    root: {}\nauthentication:\n  oidc:\n{siblings}    issuers:\n{issuers}audit:\n  path: {}\n",
                crate::runtime::RUNTIME_API_VERSION,
                crate::runtime::RUNTIME_KIND,
                self.home.join("bundle").display(),
                self.home.display(),
                self.home.join("audit").join("render.jsonl").display(),
            );
            let path = self.home.join("runtime.yaml");
            std::fs::write(&path, runtime).expect("write the runtime file");
            let (loaded, _) = crate::runtime::load_with_positions(&path, declared)
                .expect("the runtime file loads");
            callers(&loaded.config).await
        }

        /// A token signed by the key of issuer `name`.
        pub(crate) fn token(&self, name: &str, header_typ: &str, overrides: Value) -> String {
            let key = &self.keys[name];
            let now = chrono::Utc::now().timestamp();
            let mut claims = json!({"sub":"canary-principal","aud":"urn:render:test","iat":now,"exp":now+300,"scope":"render:render"});
            claims
                .as_object_mut()
                .unwrap()
                .extend(overrides.as_object().unwrap().clone());
            let header = json!({"alg":"ES256","kid":key.kid,"typ":header_typ});
            let encoded = |value: &Value| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(serde_json::to_vec(value).unwrap())
            };
            let input = format!("{}.{}", encoded(&header), encoded(&claims));
            let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sign(input.as_bytes(), key).unwrap());
            format!("{input}.{signature}")
        }
    }

    /// Two issuers over static key sets: `records` lists the client
    /// `records-service`, and `open` admits every client.
    pub(crate) const RECORDS_ISSUER: &str = "https://issuer.example.test";
    pub(crate) const OPEN_ISSUER: &str = "https://other.example.test";

    pub(crate) async fn listing_and_open_issuers(deployment: &Deployment) -> Callers {
        let issuers = format!(
            "{}{}",
            deployment.entry(
                "records",
                RECORDS_ISSUER,
                "        allowedClients: [records-service]\n"
            ),
            deployment.entry(
                "open",
                OPEN_ISSUER,
                "        allowedClients: unrestricted\n"
            ),
        );
        // An entry that admits every client is an explicit production
        // setting, so this fixture loads under development.
        deployment
            .callers_under(
                registry_platform_config::DeclaredPosture {
                    posture: registry_platform_config::Posture::Development,
                    source: registry_platform_config::PostureSource::Flag,
                },
                &issuers,
                "",
            )
            .await
            .expect("the callers build")
            .expect("the runtime declares oidc authentication")
    }

    #[test]
    fn callers_refuse_an_entry_with_no_scope_claim() {
        let entry = hs256_entry(
            "test",
            "https://issuer.example.test",
            &["portal"],
            static_keys(),
        );
        let problem = match Callers::new(
            vec![entry],
            BTreeMap::new(),
            BTreeMap::new(),
            DEFAULT_RENDER_SCOPE.to_owned(),
            DEFAULT_SEAL_SCOPE.to_owned(),
        ) {
            Err(problem) => problem,
            Ok(_) => panic!("an entry with no scope claim must be refused"),
        };
        assert_eq!(problem.kind, ProblemKind::RuntimeInvalid);
        assert!(
            problem.detail.contains("has no scope claim"),
            "{}",
            problem.detail
        );
    }

    #[tokio::test]
    async fn a_client_another_issuer_lists_is_not_named_by_an_issuer_that_admits_every_client() {
        let deployment = Deployment::new(&["records", "open"]);
        let callers = listing_and_open_issuers(&deployment).await;
        let token = |name: &str, iss: &str, client: &str| {
            deployment.token(name, "at+jwt", json!({"iss":iss,"client_id":client}))
        };
        let named = callers
            .authenticate(
                &token("records", RECORDS_ISSUER, "records-service"),
                Route::Render,
            )
            .await
            .expect("the listing issuer's token");
        assert_eq!(named.client_id.as_deref(), Some("records-service"));
        let unnamed = callers
            .authenticate(
                &token("open", OPEN_ISSUER, "records-service"),
                Route::Render,
            )
            .await
            .expect("the open issuer admits the token");
        assert_eq!(unnamed.client_id, None);
        let other = callers
            .authenticate(&token("open", OPEN_ISSUER, "batch"), Route::Render)
            .await
            .expect("a client no entry lists");
        assert_eq!(other.client_id.as_deref(), Some("batch"));
    }

    const STAFF: &str = "https://id.example.test/realms/staff";
    const PARTNERS: &str = "https://login.partner.example/v2.0";

    async fn one_issuer(deployment: &Deployment, members: &str, siblings: &str) -> Callers {
        deployment
            .callers(&deployment.entry("staff", STAFF, members), siblings)
            .await
            .expect("the callers build")
            .expect("the runtime declares oidc authentication")
    }

    fn refused_check(
        result: Result<Authenticated, AuthenticationError>,
    ) -> (FailedCheck, Option<&'static str>) {
        match result {
            Err(AuthenticationError::Refused { check, remedy }) => (check, remedy),
            other => panic!("expected a refusal, found {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_jwt_typed_token_is_refused_by_default_and_the_log_names_the_setting() {
        let deployment = Deployment::new(&["staff"]);
        let callers = one_issuer(&deployment, "        allowedClients: [portal]\n", "").await;
        let credential =
            deployment.token("staff", "JWT", json!({"iss":STAFF,"client_id":"portal"}));
        let (check, remedy) = refused_check(callers.authenticate(&credential, Route::Render).await);
        assert_eq!(check, FailedCheck::TokenType);
        assert!(
            remedy.is_some_and(|remedy| remedy.contains("accessTokenType")),
            "{remedy:?}"
        );
    }

    #[tokio::test]
    async fn a_jwt_typed_token_is_admitted_when_the_issuer_states_it() {
        let deployment = Deployment::new(&["staff"]);
        let callers = one_issuer(
            &deployment,
            "        allowedClients: [portal]\n        accessTokenType: JWT\n",
            "",
        )
        .await;
        let credential =
            deployment.token("staff", "JWT", json!({"iss":STAFF,"client_id":"portal"}));
        callers
            .authenticate(&credential, Route::Render)
            .await
            .expect("an access token typed JWT is admitted under accessTokenType: JWT");
    }

    #[tokio::test]
    async fn an_id_token_is_refused_whether_or_not_jwt_is_admitted() {
        let deployment = Deployment::new(&["staff"]);
        for members in [
            "        allowedClients: [portal]\n",
            "        allowedClients: [portal]\n        accessTokenType: JWT\n",
        ] {
            let callers = one_issuer(&deployment, members, "").await;
            for (typ, markers) in [
                ("JWT", json!({"nonce":"canary-nonce"})),
                ("JWT", json!({"at_hash":"canary-hash"})),
            ] {
                let mut claims = json!({"iss":STAFF,"client_id":"portal"});
                claims
                    .as_object_mut()
                    .unwrap()
                    .extend(markers.as_object().unwrap().clone());
                let credential = deployment.token("staff", typ, claims);
                let (check, _) =
                    refused_check(callers.authenticate(&credential, Route::Render).await);
                assert_eq!(check, FailedCheck::TokenType, "{members}{typ}");
            }
        }
    }

    #[tokio::test]
    async fn a_token_without_a_kind_authenticates_as_unspecified() {
        let deployment = Deployment::new(&["staff"]);
        let callers = one_issuer(&deployment, "        allowedClients: [portal]\n", "").await;
        let credential =
            deployment.token("staff", "at+jwt", json!({"iss":STAFF,"client_id":"portal"}));
        let caller = callers.issuers.verify(&credential).await.expect("verified");
        assert_eq!(caller.kind, CallerKind::Unspecified);
        callers
            .authenticate(&credential, Route::Render)
            .await
            .expect("Render never reads the kind");
    }

    #[tokio::test]
    async fn a_declared_client_kind_admits_a_token_without_a_kind() {
        let deployment = Deployment::new(&["staff"]);
        let callers = one_issuer(
            &deployment,
            "        allowedClients: [portal]\n        clientActorKinds:\n          portal: service\n",
            "",
        )
        .await;
        let identity_only = deployment.token(
            "staff",
            "at+jwt",
            json!({"iss":STAFF,"client_id":"portal","scope":"openid profile"}),
        );
        let caller = callers
            .issuers
            .verify(&identity_only)
            .await
            .expect("a declared kind admits an identity-only token at authentication");
        assert_eq!(caller.kind, CallerKind::Declared(ActorKind::Service));
        // The route still requires its scope: the token has none.
        assert!(matches!(
            callers.authenticate(&identity_only, Route::Render).await,
            Err(AuthenticationError::Forbidden {
                check: FailedCheck::Scope,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn a_token_kind_that_contradicts_the_declared_kind_is_refused() {
        let deployment = Deployment::new(&["staff"]);
        let callers = one_issuer(
            &deployment,
            "        allowedClients: [portal]\n        clientActorKinds:\n          portal: service\n",
            "",
        )
        .await;
        let credential = deployment.token(
            "staff",
            "at+jwt",
            json!({"iss":STAFF,"client_id":"portal","registry_actor_kind":"human"}),
        );
        let (check, _) = refused_check(callers.authenticate(&credential, Route::Render).await);
        assert_eq!(check, FailedCheck::ActorKind);
    }

    #[tokio::test]
    async fn an_unlisted_client_is_refused() {
        let deployment = Deployment::new(&["staff"]);
        let callers = one_issuer(&deployment, "        allowedClients: [portal]\n", "").await;
        let credential =
            deployment.token("staff", "at+jwt", json!({"iss":STAFF,"client_id":"other"}));
        let (check, _) = refused_check(callers.authenticate(&credential, Route::Render).await);
        assert_eq!(check, FailedCheck::TokenClient);
    }

    #[tokio::test]
    async fn an_identity_only_token_is_refused_without_a_declared_kind() {
        let deployment = Deployment::new(&["staff"]);
        let callers = one_issuer(&deployment, "        allowedClients: [portal]\n", "").await;
        let credential = deployment.token(
            "staff",
            "at+jwt",
            json!({"iss":STAFF,"client_id":"portal","scope":"openid profile email"}),
        );
        let (check, _) = refused_check(callers.authenticate(&credential, Route::Render).await);
        assert_eq!(check, FailedCheck::ActorKind);
    }

    /// Two issuers with their own rules: `staff` reads the default scope
    /// claim and admits `at+jwt`, `partners` reads `scp` and admits `JWT`.
    async fn two_issuers(deployment: &Deployment, siblings: &str) -> Callers {
        let issuers = format!(
            "{}{}",
            deployment.entry("staff", STAFF, "        allowedClients: [portal]\n"),
            deployment.entry(
                "partners",
                PARTNERS,
                "        allowedClients: [batch]\n        accessTokenType: JWT\n        scopeClaim: scp\n"
            ),
        );
        deployment
            .callers(&issuers, siblings)
            .await
            .expect("the callers build")
            .expect("the runtime declares oidc authentication")
    }

    #[tokio::test]
    async fn a_token_from_each_configured_issuer_is_verified_under_its_own_rules() {
        let deployment = Deployment::new(&["staff", "partners"]);
        let callers = two_issuers(&deployment, "").await;
        let staff = deployment.token("staff", "at+jwt", json!({"iss":STAFF,"client_id":"portal"}));
        let partners = deployment.token(
            "partners",
            "JWT",
            json!({"iss":PARTNERS,"client_id":"batch","scp":"render:render"}),
        );
        callers
            .authenticate(&staff, Route::Render)
            .await
            .expect("the staff issuer's token");
        callers
            .authenticate(&partners, Route::Render)
            .await
            .expect("the partners issuer's token, typed JWT with scopes in scp");
        // Each entry's rules apply to its own tokens only.
        let staff_typed_jwt =
            deployment.token("staff", "JWT", json!({"iss":STAFF,"client_id":"portal"}));
        let (check, _) = refused_check(callers.authenticate(&staff_typed_jwt, Route::Render).await);
        assert_eq!(check, FailedCheck::TokenType);
        let partners_without_scp = deployment.token(
            "partners",
            "JWT",
            json!({"iss":PARTNERS,"client_id":"batch","scope":null,"scp":"documents:read"}),
        );
        match callers
            .authenticate(&partners_without_scp, Route::Render)
            .await
        {
            Err(AuthenticationError::Forbidden { scope_claim, .. }) => {
                assert_eq!(
                    scope_claim, "scp",
                    "the refusal names the entry's own claim"
                );
            }
            other => panic!("expected a scope refusal, found {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_token_naming_one_issuer_signed_by_the_other_is_refused() {
        let deployment = Deployment::new(&["staff", "partners"]);
        let callers = two_issuers(&deployment, "").await;
        let credential = deployment.token(
            "partners",
            "at+jwt",
            json!({"iss":STAFF,"client_id":"portal"}),
        );
        let (check, _) = refused_check(callers.authenticate(&credential, Route::Render).await);
        assert!(
            matches!(check, FailedCheck::TokenKey | FailedCheck::TokenSignature),
            "{check:?}"
        );
    }

    #[tokio::test]
    async fn a_token_from_an_unconfigured_issuer_is_refused() {
        let deployment = Deployment::new(&["staff", "partners"]);
        let callers = two_issuers(&deployment, "").await;
        let credential = deployment.token(
            "staff",
            "at+jwt",
            json!({"iss":"https://elsewhere.example.test","client_id":"portal"}),
        );
        let (check, _) = refused_check(callers.authenticate(&credential, Route::Render).await);
        assert_eq!(check, FailedCheck::TokenIssuer);
    }

    #[tokio::test]
    async fn a_configured_scope_name_is_required_on_its_route_only() {
        let deployment = Deployment::new(&["staff"]);
        let callers = one_issuer(
            &deployment,
            "        allowedClients: [portal]\n",
            "    renderScope: documents:render\n    sealScope: documents:seal\n",
        )
        .await;
        assert_eq!(callers.scope(Route::Render), "documents:render");
        assert_eq!(callers.scope(Route::Seal), "documents:seal");
        let with = |scope: &str| {
            deployment.token(
                "staff",
                "at+jwt",
                json!({"iss":STAFF,"client_id":"portal","scope":scope}),
            )
        };
        // The defaults grant nothing once the names are configured.
        for scope in ["render:render", "render:seal"] {
            for route in [Route::Render, Route::Seal] {
                assert!(
                    matches!(
                        callers.authenticate(&with(scope), route).await,
                        Err(AuthenticationError::Forbidden { .. })
                    ),
                    "{scope} on {route:?}"
                );
            }
        }
        callers
            .authenticate(&with("documents:render"), Route::Render)
            .await
            .expect("the configured render scope");
        callers
            .authenticate(&with("documents:seal"), Route::Seal)
            .await
            .expect("the configured seal scope");
        assert!(callers
            .authenticate(&with("documents:render"), Route::Seal)
            .await
            .is_err());
    }

    /// Builds the callers from a runtime file whose static key set is `keys`.
    async fn callers_over_static_keys(keys: &Value) -> Result<Option<Callers>, RenderProblem> {
        use std::os::unix::fs::PermissionsExt;
        let scratch = tempfile::tempdir().expect("home directory");
        let home = scratch
            .path()
            .canonicalize()
            .expect("physical home directory");
        std::fs::create_dir(home.join("bundle")).expect("package directory");
        std::fs::create_dir(home.join("audit")).expect("audit directory");
        let key_file = home.join("jwks.json");
        std::fs::write(&key_file, keys.to_string()).expect("write the key set");
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only key file");
        let runtime = format!(
            "apiVersion: {}\nkind: {}\nlistener:\n  bind: 127.0.0.1:18080\npackage:\n  root: {}\nsecretProviders:\n  file:\n    root: {}\nauthentication:\n  oidc:\n    issuers:\n      main:\n        issuer: https://issuer.example.test\n        audience: urn:render:test\n        allowedClients: [portal]\n        jwksSource:\n          type: static\n          documentRef: secret:file/jwks.json\naudit:\n  path: {}\n",
            crate::runtime::RUNTIME_API_VERSION,
            crate::runtime::RUNTIME_KIND,
            home.join("bundle").display(),
            home.display(),
            home.join("audit").join("render.jsonl").display(),
        );
        let path = home.join("runtime.yaml");
        std::fs::write(&path, runtime).expect("write the runtime file");
        let (runtime, _) = crate::runtime::load(&path).expect("the runtime file loads");
        callers(&runtime).await
    }

    fn ec_public_key() -> Value {
        let set = registry_platform_testing::TokenSigner::new().public_key_set();
        set["keys"]
            .as_array()
            .expect("a key set lists keys")
            .iter()
            .find(|key| key["kty"] == "EC")
            .expect("the corpus holds an EC key")
            .clone()
    }

    #[tokio::test]
    async fn a_static_key_set_with_unknown_public_members_loads() {
        let mut key = ec_public_key();
        key["ext"] = json!(true);
        let callers = callers_over_static_keys(&json!({ "keys": [key] }))
            .await
            .expect("a public member the verifier does not read is ignored");
        assert!(callers.is_some());
    }

    #[tokio::test]
    async fn a_static_key_set_with_a_private_member_is_refused_with_the_reason() {
        let mut key = ec_public_key();
        key["d"] = json!("private");
        let problem = match callers_over_static_keys(&json!({ "keys": [key] })).await {
            Err(problem) => problem,
            Ok(_) => panic!("a key set holding a private member must be refused"),
        };
        assert_eq!(problem.kind, ProblemKind::RuntimeInvalid);
        assert!(
            problem.detail.contains("private-key member \"d\""),
            "the detail names the refused member: {}",
            problem.detail
        );
        assert!(
            problem
                .detail
                .contains("authentication.oidc.issuers.main.jwksSource"),
            "the detail names the setting: {}",
            problem.detail
        );
    }
}
