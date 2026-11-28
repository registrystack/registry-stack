use super::*;
use crate::{
    ActorKind, JwksFetcher, JwksFetcherConfig, OidcError, TokenVerifier, TokenVerifierConfig,
    DEFAULT_DOC_BYTES,
};
use axum::{routing::get, Json, Router};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use registry_platform_authcommon::FailedCheck;
use registry_platform_httputil::FetchUrlPolicy;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::net::TcpListener;

const ISSUER_A: &str = "https://a.example.org";
const ISSUER_B: &str = "https://b.example.org";
const SECRET_A: &[u8] = b"secret-a-secret-a-secret-a-secret-a";
const SECRET_B: &[u8] = b"secret-b-secret-b-secret-b-secret-b";

async fn serve_jwks(kid: &str, secret: &[u8]) -> String {
    let document = json!({"keys": [{
        "kty": "oct", "kid": kid, "alg": "HS256",
        "k": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, secret),
    }]});
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let app = Router::new().route(
        "/jwks",
        get(move || {
            let document = document.clone();
            async move { Json(document) }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{address}/jwks")
}

fn fetcher_config() -> JwksFetcherConfig {
    JwksFetcherConfig {
        cache_ttl: Duration::from_secs(3600),
        negative_cache_ttl: Duration::from_secs(3600),
        refresh_cooldown: Duration::from_secs(3600),
        max_doc_bytes: DEFAULT_DOC_BYTES,
        request_timeout: Duration::from_secs(1),
        outage_tolerance: Duration::from_secs(3600),
    }
}

async fn verifier(
    issuer: &str,
    kid: &str,
    secret: &[u8],
    typ: &str,
    clients: Vec<String>,
) -> TokenVerifier {
    let uri = serve_jwks(kid, secret).await;
    let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        uri,
        fetcher_config(),
        FetchUrlPolicy::https_or_loopback(),
    ));
    let config = TokenVerifierConfig::access_token_profile(
        issuer,
        vec!["registry-api".to_owned()],
        vec![Algorithm::HS256],
        crate::access_token_typ_set(typ),
    )
    .with_allowed_clients(clients);
    TokenVerifier::new(config, fetcher)
}

fn sign(kid: &str, secret: &[u8], typ: Option<&str>, claims: Value) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(kid.to_owned());
    header.typ = typ.map(ToOwned::to_owned);
    encode(&header, &claims, &EncodingKey::from_secret(secret)).expect("sign")
}

fn claims(issuer: &str, extra: Value) -> Value {
    let mut base = json!({
        "iss": issuer, "aud": "registry-api", "sub": "user-1", "client_id": "case-portal",
        "exp": 4_102_444_800_i64, "iat": 1_700_000_000_i64, "scope": "records.read",
    });
    for (key, value) in extra.as_object().expect("object") {
        if value.is_null() {
            base.as_object_mut().unwrap().remove(key);
        } else {
            base[key] = value.clone();
        }
    }
    base
}

fn issuers(entries: Vec<IssuerEntry>) -> Result<IssuerSet, IssuerSetError> {
    IssuerSet::new(entries, ClaimNames::default())
}

async fn set_of_two() -> IssuerSet {
    issuers(vec![
        IssuerEntry::new(
            "staff",
            verifier(
                ISSUER_A,
                "a-key",
                SECRET_A,
                "at+jwt",
                vec!["case-portal".into()],
            )
            .await,
            DeclaredKinds::None,
        ),
        IssuerEntry::new(
            "partners",
            verifier(
                ISSUER_B,
                "b-key",
                SECRET_B,
                "at+jwt",
                vec!["partner-batch".into()],
            )
            .await,
            DeclaredKinds::None,
        ),
    ])
    .expect("a set of two distinct issuers")
}

#[tokio::test]
async fn an_empty_set_is_refused_at_construction() {
    assert!(matches!(issuers(Vec::new()), Err(IssuerSetError::Empty)));
}

#[tokio::test]
async fn two_entries_with_one_issuer_are_refused_at_construction() {
    let first = verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await;
    let second = verifier(ISSUER_A, "b-key", SECRET_B, "at+jwt", vec![]).await;
    let refused = issuers(vec![
        IssuerEntry::new("staff", first, DeclaredKinds::None),
        IssuerEntry::new("partners", second, DeclaredKinds::None),
    ]);
    match refused {
        Err(IssuerSetError::DuplicateIss { first, second }) => {
            assert_eq!((first.as_str(), second.as_str()), ("staff", "partners"));
        }
        other => panic!("expected a duplicate issuer, got {other:?}"),
    }
}

#[tokio::test]
async fn a_token_is_verified_by_the_entry_its_issuer_names() {
    let set = set_of_two().await;
    let a = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(ISSUER_A, json!({})),
    );
    let verified = set.verify(&a).await.expect("entry A verifies A");
    assert_eq!(&*verified.issuer_id, "staff");
    assert_eq!(verified.token.scopes, ["records.read"]);
    let b = sign(
        "b-key",
        SECRET_B,
        Some("at+jwt"),
        claims(ISSUER_B, json!({"client_id": "partner-batch"})),
    );
    let verified = set.verify(&b).await.expect("entry B verifies B");
    assert_eq!(&*verified.issuer_id, "partners");
}

#[tokio::test]
async fn an_issuer_no_entry_names_is_refused_as_a_token_issuer_failure() {
    let set = set_of_two().await;
    let token = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims("https://stranger.example.org", json!({})),
    );
    let refused = set.verify(&token).await.unwrap_err();
    assert!(matches!(refused.error, OidcError::IssuerNotConfigured));
    assert_eq!(refused.failed_check(), FailedCheck::TokenIssuer);
}

#[tokio::test]
async fn a_token_without_an_issuer_or_not_a_token_is_refused_without_reaching_a_verifier() {
    let set = set_of_two().await;
    let no_issuer = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(ISSUER_A, json!({"iss": null})),
    );
    assert!(matches!(
        set.verify(&no_issuer).await.unwrap_err().error,
        OidcError::IssuerNotConfigured
    ));
    let refused = set.verify("not-a-token").await.unwrap_err();
    assert!(
        matches!(refused.error, OidcError::MalformedToken),
        "{refused:?}"
    );
    assert_eq!(refused.failed_check(), FailedCheck::CredentialMalformed);
}

fn segment(value: &Value) -> String {
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        serde_json::to_vec(value).unwrap(),
    )
}

#[tokio::test]
async fn a_credential_that_is_not_a_signed_token_is_refused_as_malformed() {
    let set = set_of_two().await;
    let header = segment(&json!({"alg": "HS256", "typ": "at+jwt", "kid": "a-key"}));
    let payload = segment(&json!({"iss": ISSUER_A}));
    let array = segment(&json!([ISSUER_A]));
    let not_json = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b"not json",
    );
    for credential in [
        "sb_publishable_synthetic".to_owned(),
        format!("{header}.{payload}"),
        format!("{header}.{payload}.sig.extra"),
        format!("not-base64!.{payload}.sig"),
        format!("{payload}.{payload}.sig"),
        format!("{header}.{not_json}.sig"),
        format!("{header}.{array}.sig"),
    ] {
        let refused = set.verify(&credential).await.unwrap_err();
        assert!(
            matches!(refused.error, OidcError::MalformedToken),
            "{credential}: {refused:?}"
        );
    }
}

#[tokio::test]
async fn a_wrongly_typed_claim_is_not_read_as_an_unknown_issuer() {
    let set = set_of_two().await;
    let bad_time = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(ISSUER_A, json!({"exp": "tomorrow"})),
    );
    let refused = set.verify(&bad_time).await.unwrap_err();
    assert!(
        matches!(refused.error, OidcError::InvalidTimeClaims),
        "{refused:?}"
    );
    let bad_audience = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(ISSUER_A, json!({"aud": 7})),
    );
    let refused = set.verify(&bad_audience).await.unwrap_err();
    assert_ne!(
        refused.failed_check(),
        FailedCheck::TokenIssuer,
        "{refused:?}"
    );
}

#[tokio::test]
async fn an_unknown_or_unreadable_issuer_is_refused_before_any_key_work() {
    let set = set_of_two().await;
    for extra in [
        json!({"iss": "https://stranger.example.org", "aud": 7}),
        json!({"iss": 7}),
        json!({"iss": ""}),
    ] {
        // The kid names no key of any entry: reaching a verifier would refuse it
        // at the key check instead.
        let token = sign(
            "no-such-key",
            SECRET_A,
            Some("at+jwt"),
            claims(ISSUER_A, extra),
        );
        let refused = set.verify(&token).await.unwrap_err();
        assert!(
            matches!(refused.error, OidcError::IssuerNotConfigured),
            "{refused:?}"
        );
    }
}

#[tokio::test]
async fn a_token_signed_with_b_s_key_that_names_a_is_refused_by_a() {
    let set = set_of_two().await;
    let other_key = sign(
        "b-key",
        SECRET_B,
        Some("at+jwt"),
        claims(ISSUER_A, json!({})),
    );
    let refused = set.verify(&other_key).await.unwrap_err();
    assert_eq!(refused.failed_check(), FailedCheck::TokenKey);
    let same_kid = sign(
        "a-key",
        SECRET_B,
        Some("at+jwt"),
        claims(ISSUER_A, json!({})),
    );
    let refused = set.verify(&same_kid).await.unwrap_err();
    assert_eq!(refused.failed_check(), FailedCheck::TokenSignature);
}

#[tokio::test]
async fn an_entry_never_admits_another_entry_s_client() {
    let set = set_of_two().await;
    let token = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(ISSUER_A, json!({"client_id": "partner-batch"})),
    );
    let refused = set.verify(&token).await.unwrap_err();
    assert_eq!(refused.failed_check(), FailedCheck::TokenClient);
}

#[tokio::test]
async fn the_default_type_admits_only_a_token_typed_at_jwt() {
    let verifier = verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await;
    for typ in ["at+jwt", "application/at+jwt"] {
        let token = sign("a-key", SECRET_A, Some(typ), claims(ISSUER_A, json!({})));
        verifier.verify(&token).await.expect(typ);
    }
    for typ in [Some("JWT"), Some("ID"), None] {
        let token = sign("a-key", SECRET_A, typ, claims(ISSUER_A, json!({})));
        let refused = verifier.verify(&token).await.unwrap_err();
        assert_eq!(refused.failed_check(), FailedCheck::TokenType, "{typ:?}");
    }
}

#[tokio::test]
async fn the_default_type_leaves_a_typed_token_with_an_id_claim_to_its_other_checks() {
    let verifier = verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await;
    let token = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(ISSUER_A, json!({"nonce": "n"})),
    );
    verifier
        .verify(&token)
        .await
        .expect("the type is the check here");
}

#[tokio::test]
async fn under_jwt_each_id_token_marker_is_refused_as_a_token_type_failure() {
    let verifier = verifier(ISSUER_A, "a-key", SECRET_A, "JWT", vec![]).await;
    let plain = sign("a-key", SECRET_A, Some("JWT"), claims(ISSUER_A, json!({})));
    verifier.verify(&plain).await.expect("a plain access token");
    for (name, extra) in [
        ("nonce", json!({"nonce": "n"})),
        ("at_hash", json!({"at_hash": "h"})),
        ("c_hash", json!({"c_hash": "h"})),
        ("s_hash", json!({"s_hash": "h"})),
        ("typ ID", json!({"typ": "ID"})),
        ("typ id", json!({"typ": "id"})),
    ] {
        let token = sign("a-key", SECRET_A, Some("JWT"), claims(ISSUER_A, extra));
        let refused = verifier.verify(&token).await.unwrap_err();
        assert!(
            matches!(refused, OidcError::IdTokenPresented),
            "{name}: {refused:?}"
        );
        assert_eq!(refused.failed_check(), FailedCheck::TokenType, "{name}");
    }
}

#[tokio::test]
async fn a_typ_claim_other_than_id_is_not_a_marker() {
    let verifier = verifier(ISSUER_A, "a-key", SECRET_A, "JWT", vec![]).await;
    let token = sign(
        "a-key",
        SECRET_A,
        Some("JWT"),
        claims(ISSUER_A, json!({"typ": "access"})),
    );
    verifier
        .verify(&token)
        .await
        .expect("not an ID token marker");
}

#[tokio::test]
async fn the_marker_refusal_is_on_exactly_when_the_type_set_holds_jwt() {
    let config = |typ: &str| {
        TokenVerifierConfig::access_token_profile(
            ISSUER_A,
            vec!["registry-api".to_owned()],
            vec![Algorithm::HS256],
            crate::access_token_typ_set(typ),
        )
    };
    assert!(config("JWT").refuses_id_token_markers());
    assert!(config("jwt").refuses_id_token_markers());
    assert!(!config("at+jwt").refuses_id_token_markers());
    assert!(!config("application/at+jwt").refuses_id_token_markers());
}

#[tokio::test]
async fn a_declared_kind_applies_and_a_contradicting_claim_is_refused() {
    let declared = issuers(vec![IssuerEntry::new(
        "staff",
        verifier(
            ISSUER_A,
            "a-key",
            SECRET_A,
            "at+jwt",
            vec!["case-portal".into()],
        )
        .await,
        DeclaredKinds::Clients(
            [("case-portal".to_owned(), ActorKind::Human)]
                .into_iter()
                .collect(),
        ),
    )])
    .unwrap();
    let token = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(ISSUER_A, json!({})),
    );
    let verified = declared.verify(&token).await.unwrap();
    assert_eq!(verified.kind, CallerKind::Declared(ActorKind::Human));
    let contradicting = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(ISSUER_A, json!({"registry_actor_kind": "service"})),
    );
    let refused = declared.verify(&contradicting).await.unwrap_err();
    assert!(matches!(refused.error, OidcError::ActorKindConflict));
    assert_eq!(refused.failed_check(), FailedCheck::ActorKind);
}

#[tokio::test]
async fn an_identity_only_token_is_refused_unless_the_client_s_kind_is_declared() {
    let bare = |kid: &str, secret: &[u8]| {
        sign(
            kid,
            secret,
            Some("at+jwt"),
            claims(ISSUER_A, json!({"scope": null})),
        )
    };
    let undeclared = issuers(vec![IssuerEntry::new(
        "staff",
        verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await,
        DeclaredKinds::None,
    )])
    .unwrap();
    let refused = undeclared
        .verify(&bare("a-key", SECRET_A))
        .await
        .unwrap_err();
    assert!(matches!(refused.error, OidcError::IdentityOnly));
    assert_eq!(refused.failed_check(), FailedCheck::ActorKind);

    let declared = issuers(vec![IssuerEntry::new(
        "staff",
        verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await,
        DeclaredKinds::Issuer(ActorKind::Human),
    )])
    .unwrap();
    let verified = declared.verify(&bare("a-key", SECRET_A)).await.unwrap();
    assert!(verified.token.scopes.is_empty());
    assert_eq!(verified.kind, CallerKind::Declared(ActorKind::Human));
}

#[tokio::test]
async fn a_claimed_kind_or_openid_connect_scopes_alone_do_not_admit_a_token() {
    let undeclared = issuers(vec![IssuerEntry::new(
        "staff",
        verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await,
        DeclaredKinds::None,
    )])
    .unwrap();
    let declared = issuers(vec![IssuerEntry::new(
        "staff",
        verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await,
        DeclaredKinds::Issuer(ActorKind::Service),
    )])
    .unwrap();
    for extra in [
        json!({"scope": null, "registry_actor_kind": "service"}),
        json!({"scope": "openid email profile"}),
        json!({"scope": "openid offline_access", "registry_actor_kind": "service"}),
    ] {
        let token = sign(
            "a-key",
            SECRET_A,
            Some("at+jwt"),
            claims(ISSUER_A, extra.clone()),
        );
        let refused = undeclared.verify(&token).await.unwrap_err();
        assert!(
            matches!(refused.error, OidcError::IdentityOnly),
            "{extra}: {refused:?}"
        );
        let verified = declared.verify(&token).await.expect("declared");
        assert_eq!(verified.kind, CallerKind::Declared(ActorKind::Service));
    }
}

async fn unrestricted_with_one_declared_client() -> IssuerSet {
    issuers(vec![IssuerEntry::new(
        "wallets",
        verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await,
        DeclaredKinds::Clients(
            [("wallet-portal".to_owned(), ActorKind::Human)]
                .into_iter()
                .collect(),
        ),
    )])
    .unwrap()
}

#[tokio::test]
async fn under_unrestricted_clients_the_kind_declared_for_azp_admits_a_token_with_no_scope() {
    let set = unrestricted_with_one_declared_client().await;
    let token = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(
            ISSUER_A,
            json!({"scope": null, "client_id": null, "azp": "wallet-portal"}),
        ),
    );
    let verified = set.verify(&token).await.expect("declared client");
    assert_eq!(verified.kind, CallerKind::Declared(ActorKind::Human));
    let undeclared = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(
            ISSUER_A,
            json!({"scope": null, "client_id": null, "azp": "other-portal"}),
        ),
    );
    let refused = set.verify(&undeclared).await.unwrap_err();
    assert!(
        matches!(refused.error, OidcError::IdentityOnly),
        "{refused:?}"
    );
}

#[tokio::test]
async fn under_unrestricted_clients_client_id_names_the_client_when_azp_is_absent() {
    let set = unrestricted_with_one_declared_client().await;
    let token = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(
            ISSUER_A,
            json!({"scope": null, "client_id": "wallet-portal"}),
        ),
    );
    let verified = set
        .verify(&token)
        .await
        .expect("client_id names a declared client");
    assert_eq!(verified.kind, CallerKind::Declared(ActorKind::Human));
}

#[tokio::test]
async fn under_unrestricted_clients_azp_names_the_client_before_client_id() {
    let set = unrestricted_with_one_declared_client().await;
    let azp_declared = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(
            ISSUER_A,
            json!({"scope": null, "azp": "wallet-portal", "client_id": "other-portal"}),
        ),
    );
    let verified = set.verify(&azp_declared).await.expect("azp wins");
    assert_eq!(verified.kind, CallerKind::Declared(ActorKind::Human));
    let azp_undeclared = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(
            ISSUER_A,
            json!({"scope": null, "azp": "other-portal", "client_id": "wallet-portal"}),
        ),
    );
    let refused = set.verify(&azp_undeclared).await.unwrap_err();
    assert!(
        matches!(refused.error, OidcError::IdentityOnly),
        "{refused:?}"
    );
}

#[tokio::test]
async fn two_entries_whose_issuers_differ_only_in_form_are_refused_at_construction() {
    for (first, second) in [
        ("https://a.example.org", "https://a.example.org/"),
        ("https://a.example.org/realm", "https://A.Example.org/realm"),
    ] {
        let refused = issuers(vec![
            IssuerEntry::new(
                "staff",
                verifier(first, "a-key", SECRET_A, "at+jwt", vec![]).await,
                DeclaredKinds::None,
            ),
            IssuerEntry::new(
                "partners",
                verifier(second, "b-key", SECRET_B, "at+jwt", vec![]).await,
                DeclaredKinds::None,
            ),
        ]);
        assert!(
            matches!(refused, Err(IssuerSetError::DuplicateIss { .. })),
            "{first} and {second}: {refused:?}"
        );
    }
}

#[tokio::test]
async fn a_token_with_a_scope_and_no_kind_is_unspecified_and_admitted() {
    let set = set_of_two().await;
    let token = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(ISSUER_A, json!({})),
    );
    let verified = set.verify(&token).await.unwrap();
    assert_eq!(verified.kind, CallerKind::Unspecified);
}

#[tokio::test]
async fn entries_are_listed_with_their_ids() {
    let set = set_of_two().await;
    let ids: Vec<&str> = set.entries().map(|entry| &*entry.id).collect();
    assert_eq!(ids, ["staff", "partners"]);
}

#[tokio::test]
async fn an_unreadable_kind_claim_is_refused_as_malformed_even_under_a_declaration() {
    for declared in [DeclaredKinds::None, DeclaredKinds::Issuer(ActorKind::Human)] {
        let set = issuers(vec![IssuerEntry::new(
            "staff",
            verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await,
            declared.clone(),
        )])
        .unwrap();
        for malformed in [json!("robot"), json!(7)] {
            let token = sign(
                "a-key",
                SECRET_A,
                Some("at+jwt"),
                claims(ISSUER_A, json!({"registry_actor_kind": malformed})),
            );
            let refused = set.verify(&token).await.unwrap_err();
            assert!(
                matches!(refused.error, OidcError::ActorKindMalformed),
                "{declared:?} {malformed}: {refused:?}"
            );
            assert_eq!(refused.failed_check(), FailedCheck::ActorKind);
        }
    }
}

#[tokio::test]
async fn invalid_claim_names_are_refused_when_the_set_is_built() {
    let names = ClaimNames {
        actor_kind: String::new(),
        ..ClaimNames::default()
    };
    let refused = IssuerSet::new(
        vec![IssuerEntry::new(
            "staff",
            verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await,
            DeclaredKinds::None,
        )],
        names,
    );
    assert!(
        matches!(refused, Err(IssuerSetError::InvalidClaimNames)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn the_kind_claim_is_read_with_the_set_s_claim_names() {
    let names = ClaimNames {
        actor_kind: "kind".to_owned(),
        ..ClaimNames::default()
    };
    let set = IssuerSet::new(
        vec![IssuerEntry::new(
            "staff",
            verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await,
            DeclaredKinds::None,
        )],
        names,
    )
    .unwrap();
    let token = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims(ISSUER_A, json!({"kind": "agent"})),
    );
    let verified = set.verify(&token).await.unwrap();
    assert_eq!(verified.kind, CallerKind::Claimed(ActorKind::Agent));
}

#[tokio::test]
async fn a_refusal_carries_the_remedy_for_the_entry_that_refused() {
    let set = issuers(vec![
        IssuerEntry::new(
            "staff",
            verifier(ISSUER_A, "a-key", SECRET_A, "at+jwt", vec![]).await,
            DeclaredKinds::None,
        ),
        IssuerEntry::new(
            "partners",
            verifier(ISSUER_B, "b-key", SECRET_B, "JWT", vec![]).await,
            DeclaredKinds::None,
        ),
    ])
    .unwrap();
    let typed_jwt = sign("a-key", SECRET_A, Some("JWT"), claims(ISSUER_A, json!({})));
    let refused = set.verify(&typed_jwt).await.unwrap_err();
    assert!(matches!(refused.error, OidcError::TokenTypeNotAllowed));
    assert_eq!(
        refused.remedy,
        OidcError::TokenTypeNotAllowed.remedy(false),
        "an at+jwt entry"
    );
    let typed_at_jwt = sign(
        "b-key",
        SECRET_B,
        Some("at+jwt"),
        claims(ISSUER_B, json!({})),
    );
    let refused = set.verify(&typed_at_jwt).await.unwrap_err();
    assert!(matches!(refused.error, OidcError::TokenTypeNotAllowed));
    assert_eq!(
        refused.remedy,
        OidcError::TokenTypeNotAllowed.remedy(true),
        "a JWT entry"
    );
    let id_token = sign(
        "b-key",
        SECRET_B,
        Some("JWT"),
        claims(ISSUER_B, json!({"nonce": "n"})),
    );
    let refused = set.verify(&id_token).await.unwrap_err();
    assert!(matches!(refused.error, OidcError::IdTokenPresented));
    assert_eq!(refused.remedy, OidcError::IdTokenPresented.remedy(true));
    let stranger = sign(
        "a-key",
        SECRET_A,
        Some("at+jwt"),
        claims("https://stranger.example.org", json!({})),
    );
    let refused = set.verify(&stranger).await.unwrap_err();
    assert!(refused
        .remedy
        .is_some_and(|remedy| remedy.contains("issuers")));
    let refused = set.verify("not-a-token").await.unwrap_err();
    assert_eq!(refused.remedy, None);
}
