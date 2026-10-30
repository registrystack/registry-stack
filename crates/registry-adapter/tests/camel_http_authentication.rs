// SPDX-License-Identifier: Apache-2.0

//! The upstream authentication kinds of `products/adapter/CONCEPT.md`
//! section 10.2, exercised over a real loopback HTTP double: each kind
//! compiles against its runtime binding and produces exactly the
//! credential carriage the concept states, the token endpoint answers
//! are read as Evidence reads them, and the marker-secret test proves a
//! recognizable secret travels only in that carriage.
//!
//! The 401 refresh loop (invalidate, resend once, then the uncatchable
//! `credential.rejected`) is the engine's to drive against the upstream
//! data send; this file proves the auth layer's half of it, the rule
//! itself, in the unit suite.

#[path = "support/upstream/mod.rs"]
mod upstream;

use registry_adapter::auth::{
    AuthError, AuthEvent, AuthPlan, AuthorizeContext, AuthorizedCredential, ClientAssertion,
    ClientAssertionSigner, ProtectedText, TokenBudget, CREDENTIAL_REJECTED_CLASS,
    UNREGISTERED_ERROR_CODE,
};
use registry_adapter_core::{
    CredentialPlacement, EndpointAuthentication, EndpointBinding, RuntimeCredential,
};
use registry_platform_config::SecretResolver;
use registry_platform_yaml::{BoundedU64, ExternalId, SecretProvider, SecretReference, Url};
use upstream::{LoopbackSend, Response, UpstreamDouble};

/// The recognizable secret the marker test hunts for; no deployment has
/// ever used it.
const MARKER_SECRET: &str =
    "C4A-MARKER-7f3d9a1e5b2c8d4f6a0e3b1c9d7f5a2e8b4c6d0f2a8e5b3c7d1f9a4e6b2c8d0f6";

/// A signer that binds the resolved key into its assertion, the way a
/// real signature is bound to its key, so key text is traceable in the
/// record.
struct KeyBindingSigner;

impl ClientAssertionSigner for KeyBindingSigner {
    fn sign_client_assertion(
        &self,
        request: ClientAssertion<'_>,
    ) -> Result<ProtectedText, AuthError> {
        Ok(ProtectedText::from_str_value(&format!(
            "assertion.{}.{}.{}",
            request.client_id,
            request.audience,
            String::from_utf8_lossy(request.key.as_bytes())
        )))
    }
}

fn secret(name: &str) -> SecretReference {
    SecretReference::new(format!("secret:env/{name}")).expect("secret reference")
}

fn resolver() -> SecretResolver {
    SecretResolver::new([SecretProvider::Environment], "").expect("resolver")
}

fn binding(base_url: &str, credential: Option<RuntimeCredential>) -> EndpointBinding {
    EndpointBinding {
        endpoint: ExternalId::new("case-api").expect("id"),
        base_url: Url::new(base_url).expect("url"),
        credential,
        tls_trust_profile: None,
        mtls_identity: None,
    }
}

fn oauth_binding(
    token_endpoint: &str,
    client_id_env: &str,
    secret_env: &str,
    placement: CredentialPlacement,
) -> EndpointBinding {
    binding(
        "https://cases.example.invalid",
        Some(RuntimeCredential::Oauth2ClientCredentials {
            token_endpoint: Url::new(token_endpoint).expect("url"),
            client_id_ref: secret(client_id_env),
            client_secret_ref: secret(secret_env),
            scope: None,
            audience: None,
            resource: None,
            credential_placement: placement,
            maximum_cache_seconds: BoundedU64::new(3600).expect("cache"),
            assumed_lifetime_seconds: None,
        }),
    )
}

async fn authorize_with_plan(
    plan: &registry_adapter::auth::AuthPlan,
    send: &dyn registry_adapter::auth::TokenSend,
    events: &mut Vec<AuthEvent>,
) -> Result<Option<AuthorizedCredential>, AuthError> {
    let mut budget = TokenBudget::new_exchange();
    let mut context = AuthorizeContext {
        resolver: &resolver(),
        budget: &mut budget,
        send,
        signer: &KeyBindingSigner,
        events,
    };
    plan.authorize(&mut context).await
}

/// Decode standard base64 with padding, the inverse of the Basic
/// encoding, so tests can assert the exact pair that traveled.
fn base64_decode(text: &str) -> Vec<u8> {
    const INVERSE: [Option<u8>; 128] = {
        let mut table = [None; 128];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut index = 0;
        while index < 64 {
            table[alphabet[index] as usize] = Some(index as u8);
            index += 1;
        }
        table
    };
    let mut out = Vec::new();
    let mut triple = 0u32;
    let mut seen = 0u8;
    for byte in text.bytes() {
        if byte == b'=' {
            break;
        }
        let value = INVERSE[usize::from(byte)].expect("standard base64 only");
        triple = (triple << 6) | u32::from(value);
        seen += 1;
        if seen == 4 {
            out.push((triple >> 16) as u8);
            out.push((triple >> 8) as u8);
            out.push(triple as u8);
            triple = 0;
            seen = 0;
        }
    }
    match seen {
        // A two-character tail carries one byte in the low 8 of the
        // accumulated 12 bits; a three-character tail carries two bytes
        // in the accumulated 18.
        2 => {
            out.push((triple >> 4) as u8);
        }
        3 => {
            out.push((triple >> 10) as u8);
            out.push(((triple >> 2) & 0xFF) as u8);
        }
        _ => {}
    }
    out
}

/// `none` sends nothing and reaches past loopback only under mTLS.
#[tokio::test]
async fn none_sends_nothing_and_stays_loopbound() {
    let plan = AuthPlan::compile(
        &EndpointAuthentication::None {},
        &binding("http://127.0.0.1:9/", Some(RuntimeCredential::None {})),
    )
    .expect("numeric loopback admits none");
    let mut events = Vec::new();
    let credential = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
        .await
        .expect("none resolves");
    assert!(
        credential.is_none(),
        "the none kind produces no header material"
    );

    let fault = AuthPlan::compile(
        &EndpointAuthentication::None {},
        &binding(
            "https://cases.example.invalid",
            Some(RuntimeCredential::None {}),
        ),
    )
    .unwrap_err();
    assert_eq!(
        fault.to_string(),
        "a none endpoint reaches an origin that is neither numeric loopback nor https with an \
         mTLS client identity"
    );
}

/// `basic` resolves the pair preemptively into one Basic header; the
/// layer itself sends nothing.
#[tokio::test]
async fn basic_sends_one_preemptive_header() {
    std::env::set_var("ADAPTER_IT_BASIC_USER", "user");
    std::env::set_var("ADAPTER_IT_BASIC_PASS", "pass");
    let double = UpstreamDouble::start();
    let plan = AuthPlan::compile(
        &EndpointAuthentication::Basic {},
        &binding(
            "https://cases.example.invalid",
            Some(RuntimeCredential::Basic {
                username_ref: secret("ADAPTER_IT_BASIC_USER"),
                password_ref: secret("ADAPTER_IT_BASIC_PASS"),
            }),
        ),
    )
    .expect("a usable plan");
    let mut events = Vec::new();
    let credential = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
        .await
        .expect("the pair resolves")
        .expect("basic sends a header");
    assert_eq!(credential.header.name(), "authorization");
    assert_eq!(credential.header.value().as_bytes(), b"Basic dXNlcjpwYXNz");
    assert!(events.is_empty(), "a static kind records no token events");
    assert_eq!(double.request_count(), 0, "the auth layer sends nothing");
}

/// `static-authorization` presents the token under the declared scheme,
/// defaulting to `Bearer`.
#[tokio::test]
async fn static_authorization_presents_the_declared_scheme() {
    std::env::set_var("ADAPTER_IT_AUTH_TOKEN", "tok");
    let cases: [(Option<&str>, &[u8]); 2] = [
        (None, b"Bearer tok".as_slice()),
        (Some("ApiToken"), b"ApiToken tok".as_slice()),
    ];
    for (scheme, expected) in cases {
        let endpoint = EndpointAuthentication::StaticAuthorization {
            scheme: scheme.map(str::to_owned),
        };
        let plan = AuthPlan::compile(
            &endpoint,
            &binding(
                "https://cases.example.invalid",
                Some(RuntimeCredential::StaticAuthorization {
                    token_ref: secret("ADAPTER_IT_AUTH_TOKEN"),
                }),
            ),
        )
        .expect("a usable plan");
        let mut events = Vec::new();
        let credential = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
            .await
            .expect("the token resolves")
            .expect("a header is sent");
        assert_eq!(credential.header.name(), "authorization");
        assert_eq!(credential.header.value().as_bytes(), expected);
    }
}

/// `static-api-key` places the key in the declared header, which the
/// reserved-name rule keeps off the engine's own headers.
#[tokio::test]
async fn static_api_key_uses_the_declared_header() {
    std::env::set_var("ADAPTER_IT_API_KEY", "key123");
    let plan = AuthPlan::compile(
        &EndpointAuthentication::StaticApiKey {
            header_name: "X-Api-Key".to_owned(),
        },
        &binding(
            "https://cases.example.invalid",
            Some(RuntimeCredential::StaticApiKey {
                value_ref: secret("ADAPTER_IT_API_KEY"),
            }),
        ),
    )
    .expect("a usable plan");
    let mut events = Vec::new();
    let credential = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
        .await
        .expect("the key resolves")
        .expect("a header is sent");
    assert_eq!(credential.header.name(), "X-Api-Key");
    assert_eq!(credential.header.value().as_bytes(), b"key123");
}

/// The client-credentials kind takes its bearer from the fixed token
/// endpoint over the endpoint's own transport: the secret travels by its
/// declared placement and nowhere else, the answer is read as Evidence
/// reads it, the second send is a cache hit, a refusal surfaces only the
/// registered code, and the exchange budget holds two token sends.
mod oauth2_client_credentials {
    use super::*;

    /// Both placements carry the secret exactly once, in the declared
    /// place, and the issued credential becomes the bearer.
    #[tokio::test]
    async fn both_placements_carry_the_secret_once() {
        std::env::set_var("ADAPTER_IT_CC_BH_ID", "cid-bh");
        std::env::set_var("ADAPTER_IT_CC_BH_SECRET", "cc-secret-1");
        std::env::set_var("ADAPTER_IT_CC_FB_ID", "cid-fb");
        std::env::set_var("ADAPTER_IT_CC_FB_SECRET", "cc-secret-2");

        let double = UpstreamDouble::start();
        double.respond_with(vec![Response::json(
            200,
            r#"{"access_token":"issued-bh","token_type":"Bearer","expires_in":600}"#,
        )]);
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &oauth_binding(
                &double.url("/token"),
                "ADAPTER_IT_CC_BH_ID",
                "ADAPTER_IT_CC_BH_SECRET",
                CredentialPlacement::BasicHeader,
            ),
        )
        .expect("a usable plan");
        let mut events = Vec::new();
        let credential = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
            .await
            .expect("a credential issues")
            .expect("a header is sent");
        assert_eq!(credential.header.value().as_bytes(), b"Bearer issued-bh");

        let requests = double.requests();
        assert_eq!(requests.len(), 1, "one token request");
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/token");
        let basic = request
            .header("authorization")
            .expect("the Basic placement authenticates in the header");
        assert!(basic.starts_with("Basic "), "{basic}");
        let pair = base64_decode(basic.trim_start_matches("Basic "));
        assert_eq!(pair, b"cid-bh:cc-secret-1", "the exact pair traveled");
        let body = request.body_text();
        assert!(
            body.starts_with("grant_type=client_credentials"),
            "the grant comes first: {body}"
        );
        assert!(
            !body.contains("client_id"),
            "the Basic placement names the client in the header alone, never in the body: {body}"
        );
        assert!(
            !body.contains("cc-secret-1"),
            "the Basic placement never repeats the secret in the body"
        );
        assert!(
            request.header("content-type").is_some_and(|value| value
                .split(';')
                .next()
                .is_some_and(|media| media
                    .trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded"))),
            "the form body declares its media type"
        );

        let double = UpstreamDouble::start();
        double.respond_with(vec![Response::json(
            200,
            r#"{"access_token":"issued-fb","token_type":"Bearer","expires_in":600}"#,
        )]);
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &oauth_binding(
                &double.url("/token"),
                "ADAPTER_IT_CC_FB_ID",
                "ADAPTER_IT_CC_FB_SECRET",
                CredentialPlacement::FormBody,
            ),
        )
        .expect("a usable plan");
        let mut events = Vec::new();
        let credential = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
            .await
            .expect("a credential issues")
            .expect("a header is sent");
        assert_eq!(credential.header.value().as_bytes(), b"Bearer issued-fb");
        let request = &double.requests()[0];
        assert!(
            request.header("authorization").is_none(),
            "the form placement authenticates in the body only"
        );
        let body = request.body_text();
        assert!(body.contains("client_id=cid-fb"));
        assert!(
            body.contains("client_secret=cc-secret-2"),
            "the form placement carries the secret once: {body}"
        );
    }

    /// The endpoint's cache answers the second send, and a refusal
    /// surfaces the registered code name and nothing the server said.
    #[tokio::test]
    async fn the_cache_answers_and_refusals_name_only_the_code() {
        std::env::set_var("ADAPTER_IT_CC_CACHE_ID", "cid-cache");
        std::env::set_var("ADAPTER_IT_CC_CACHE_SECRET", "cc-secret-3");
        let double = UpstreamDouble::start();
        double.respond_with(vec![Response::json(
            200,
            r#"{"access_token":"issued-cache","token_type":"Bearer","expires_in":600}"#,
        )]);
        let cache_binding = oauth_binding(
            &double.url("/token"),
            "ADAPTER_IT_CC_CACHE_ID",
            "ADAPTER_IT_CC_CACHE_SECRET",
            CredentialPlacement::BasicHeader,
        );
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &cache_binding,
        )
        .expect("a usable plan");

        let cache = plan
            .token_plan()
            .expect("the OAuth2 plan carries its token endpoint")
            .cache();
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let send = LoopbackSend::new();
        let mut first = AuthorizeContext {
            resolver: &resolver(),
            budget: &mut budget,
            send: &send,
            signer: &KeyBindingSigner,
            events: &mut events,
        };
        let primed = plan
            .authorize(&mut first)
            .await
            .expect("the first credential issues")
            .expect("a header is sent");
        let mut second = AuthorizeContext {
            resolver: &resolver(),
            budget: &mut budget,
            send: &send,
            signer: &KeyBindingSigner,
            events: &mut events,
        };
        let credential = plan
            .authorize(&mut second)
            .await
            .expect("the cache answers")
            .expect("a header is sent");
        assert_eq!(credential.header.value().as_bytes(), b"Bearer issued-cache");
        assert_eq!(double.request_count(), 1, "the second send is a cache hit");
        assert!(events.contains(&AuthEvent::TokenCacheHit));

        double.respond_with(vec![Response::refused(
            401,
            "invalid_client",
            "server text about the credential",
        )]);
        // The engine's loop reaches the refusal through the 401 rule:
        // the rule invalidates the plan's cached credential before the
        // one refresh, whose send is the one the endpoint refuses.
        let mut events = Vec::new();
        let mut refresh_used = false;
        let action = plan
            .on_upstream_status(401, primed.generation, &mut refresh_used, &mut events)
            .await;
        assert_eq!(
            action,
            registry_adapter::auth::UpstreamStatusAction::RetryWithFreshCredential
        );
        assert!(cache.remaining_lifetime().await.is_none());
        let mut context = AuthorizeContext {
            resolver: &resolver(),
            budget: &mut budget,
            send: &send,
            signer: &KeyBindingSigner,
            events: &mut events,
        };
        let error = plan.authorize(&mut context).await.unwrap_err();
        assert_eq!(
            error,
            AuthError::Token(registry_adapter::auth::TokenFault::Refused {
                code: "invalid_client"
            })
        );
        assert_eq!(
            error.to_string(),
            "the token endpoint declined to issue a token: invalid_client"
        );
        assert!(!error.to_string().contains("server text"), "{error}");
    }

    /// One plan serves many exchanges: the credential an earlier
    /// exchange cached is a hit for the next, each exchange under its
    /// own budget, so the endpoint is asked once in total. Compiling per
    /// exchange would silently re-fetch on every exchange.
    #[tokio::test]
    async fn one_plan_serves_many_exchanges() {
        std::env::set_var("ADAPTER_IT_CC_REUSE_ID", "cid-reuse");
        std::env::set_var("ADAPTER_IT_CC_REUSE_SECRET", "cc-secret-7");
        let double = UpstreamDouble::start();
        double.respond_with(vec![Response::json(
            200,
            r#"{"access_token":"issued-reuse","token_type":"Bearer","expires_in":600}"#,
        )]);
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &oauth_binding(
                &double.url("/token"),
                "ADAPTER_IT_CC_REUSE_ID",
                "ADAPTER_IT_CC_REUSE_SECRET",
                CredentialPlacement::BasicHeader,
            ),
        )
        .expect("a usable plan");
        for _ in 0..2 {
            // A fresh budget each exchange, the engine's shape; the plan
            // and its cache are the deployment's, held across both.
            let mut budget = TokenBudget::new_exchange();
            let mut events = Vec::new();
            let mut context = AuthorizeContext {
                resolver: &resolver(),
                budget: &mut budget,
                send: &LoopbackSend::new(),
                signer: &KeyBindingSigner,
                events: &mut events,
            };
            let credential = plan
                .authorize(&mut context)
                .await
                .expect("a credential issues")
                .expect("a header is sent");
            assert_eq!(credential.header.value().as_bytes(), b"Bearer issued-reuse");
        }
        assert_eq!(
            double.request_count(),
            1,
            "the second exchange is a cache hit"
        );
    }

    /// A 401 whose body is not a readable error object is still the
    /// uncatchable credential rejection: the status, not the body,
    /// decides the class, so no gateway error page can let a fallback
    /// mask a dead credential.
    #[tokio::test]
    async fn a_401_with_an_unparseable_body_is_still_rejected() {
        std::env::set_var("ADAPTER_IT_CC_EMPTY_ID", "cid-empty");
        std::env::set_var("ADAPTER_IT_CC_EMPTY_SECRET", "cc-secret-6");
        let double = UpstreamDouble::start();
        double.respond_with(vec![Response {
            status: 401,
            media_type: "text/html",
            body: "<html>bad gateway</html>".to_owned(),
        }]);
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &oauth_binding(
                &double.url("/token"),
                "ADAPTER_IT_CC_EMPTY_ID",
                "ADAPTER_IT_CC_EMPTY_SECRET",
                CredentialPlacement::BasicHeader,
            ),
        )
        .expect("a usable plan");
        let mut events = Vec::new();
        let error = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            AuthError::Token(registry_adapter::auth::TokenFault::Refused {
                code: UNREGISTERED_ERROR_CODE
            })
        );
        assert_eq!(error.class(), CREDENTIAL_REJECTED_CLASS);
        assert!(!error.to_string().contains("bad gateway"), "{error}");
    }

    /// The exchange budget holds two token sends; the third refuses
    /// without a request.
    #[tokio::test]
    async fn the_budget_holds_two_sends() {
        std::env::set_var("ADAPTER_IT_CC_BUDGET_ID", "cid-budget");
        std::env::set_var("ADAPTER_IT_CC_BUDGET_SECRET", "cc-secret-4");
        let double = UpstreamDouble::start();
        double.respond_with(vec![
            Response::refused(400, "invalid_client", "first refusal"),
            Response::refused(400, "invalid_client", "second refusal"),
        ]);
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &oauth_binding(
                &double.url("/token"),
                "ADAPTER_IT_CC_BUDGET_ID",
                "ADAPTER_IT_CC_BUDGET_SECRET",
                CredentialPlacement::BasicHeader,
            ),
        )
        .expect("a usable plan");
        let endpoint = ExternalId::new("case-api").expect("id");
        let mut budget = TokenBudget::new_exchange();
        let send = LoopbackSend::new();
        for expected_remaining in [1, 0] {
            let mut events = Vec::new();
            let mut context = AuthorizeContext {
                resolver: &resolver(),
                budget: &mut budget,
                send: &send,
                signer: &KeyBindingSigner,
                events: &mut events,
            };
            let error = plan.authorize(&mut context).await.unwrap_err();
            assert_eq!(
                error,
                AuthError::Token(registry_adapter::auth::TokenFault::Refused {
                    code: "invalid_client"
                })
            );
            assert_eq!(budget.remaining(&endpoint), expected_remaining);
        }
        let mut events = Vec::new();
        let mut context = AuthorizeContext {
            resolver: &resolver(),
            budget: &mut budget,
            send: &send,
            signer: &KeyBindingSigner,
            events: &mut events,
        };
        let error = plan.authorize(&mut context).await.unwrap_err();
        assert_eq!(error, AuthError::BudgetExhausted);
        assert_eq!(error.to_string(), "the exchange's token budget is spent");
        assert_eq!(events, vec![AuthEvent::TokenBudgetExhausted]);
        assert_eq!(double.request_count(), 2, "no third request was sent");
    }

    /// A 401 from the upstream data send drives the plan's rule: one
    /// refresh with the cache invalidated, then the uncatchable
    /// credential class.
    #[tokio::test]
    async fn the_401_rule_runs_over_the_issued_credential() {
        std::env::set_var("ADAPTER_IT_CC_401_ID", "cid-401");
        std::env::set_var("ADAPTER_IT_CC_401_SECRET", "cc-secret-5");
        let double = UpstreamDouble::start();
        double.respond_with(vec![Response::json(
            200,
            r#"{"access_token":"issued-401","token_type":"Bearer","expires_in":600}"#,
        )]);
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &oauth_binding(
                &double.url("/token"),
                "ADAPTER_IT_CC_401_ID",
                "ADAPTER_IT_CC_401_SECRET",
                CredentialPlacement::BasicHeader,
            ),
        )
        .expect("a usable plan");
        let cache = plan
            .token_plan()
            .expect("the OAuth2 plan carries its token endpoint")
            .cache();
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let send = LoopbackSend::new();
        let mut context = AuthorizeContext {
            resolver: &resolver(),
            budget: &mut budget,
            send: &send,
            signer: &KeyBindingSigner,
            events: &mut events,
        };
        let primed = plan
            .authorize(&mut context)
            .await
            .expect("the credential issues")
            .expect("a header is sent");
        assert!(cache.remaining_lifetime().await.is_some());

        let mut refresh_used = false;
        let action = plan
            .on_upstream_status(401, primed.generation, &mut refresh_used, &mut events)
            .await;
        assert_eq!(
            action,
            registry_adapter::auth::UpstreamStatusAction::RetryWithFreshCredential
        );
        assert!(refresh_used);
        assert!(cache.remaining_lifetime().await.is_none());
        // The spent refresh short-circuits before the generation is read.
        let action = plan
            .on_upstream_status(401, None, &mut refresh_used, &mut events)
            .await;
        assert_eq!(
            action,
            registry_adapter::auth::UpstreamStatusAction::CredentialRejected
        );
        assert_eq!(
            AuthError::Credential.class(),
            CREDENTIAL_REJECTED_CLASS,
            "the class a route cannot catch"
        );
        let action = plan
            .on_upstream_status(403, None, &mut refresh_used, &mut events)
            .await;
        assert_eq!(
            action,
            registry_adapter::auth::UpstreamStatusAction::Continue
        );
    }
}

/// The private-key-jwt kind signs its assertion for the token endpoint
/// itself and carries it in the form body, with no Basic header.
mod oauth2_private_key_jwt {
    use super::*;

    fn pkjwt_binding(token_endpoint: &str, client_id_env: &str, key_env: &str) -> EndpointBinding {
        binding(
            "https://cases.example.invalid",
            Some(RuntimeCredential::Oauth2PrivateKeyJwt {
                token_endpoint: Url::new(token_endpoint).expect("url"),
                client_id_ref: secret(client_id_env),
                client_assertion_key_ref: secret(key_env),
                client_assertion_audience: None,
                scope: None,
                audience: None,
                resource: None,
                maximum_cache_seconds: BoundedU64::new(3600).expect("cache"),
                assumed_lifetime_seconds: None,
            }),
        )
    }

    /// The assertion travels as the last form member, bound to the token
    /// endpoint as its audience, and the issued credential is the bearer.
    #[tokio::test]
    async fn the_assertion_travels_bound_to_the_token_endpoint() {
        std::env::set_var("ADAPTER_IT_PKJWT_ID", "cid-pj");
        std::env::set_var("ADAPTER_IT_PKJWT_KEY", "pkjwt-key-pem");
        let double = UpstreamDouble::start();
        double.respond_with(vec![Response::json(
            200,
            r#"{"access_token":"issued-pj","token_type":"Bearer","expires_in":600,"ext":"ignored"}"#,
        )]);
        let token_endpoint = double.url("/token");
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2PrivateKeyJwt {},
            &pkjwt_binding(
                &token_endpoint,
                "ADAPTER_IT_PKJWT_ID",
                "ADAPTER_IT_PKJWT_KEY",
            ),
        )
        .expect("a usable plan");
        let mut events = Vec::new();
        let credential = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
            .await
            .expect("a credential issues")
            .expect("a header is sent");
        assert_eq!(credential.header.value().as_bytes(), b"Bearer issued-pj");

        let request = &double.requests()[0];
        assert!(
            request.header("authorization").is_none(),
            "the assertion kind has no Basic header"
        );
        let body = request.body_text();
        assert!(
            body.contains("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"),
            "the fixed assertion type travels: {body}"
        );
        assert!(
            body.contains("client_assertion=assertion.cid-pj.http%3A%2F%2F127.0.0.1"),
            "the audience defaults to the token endpoint as written: {body}"
        );
        assert!(
            body.ends_with(".pkjwt-key-pem"),
            "the key text travels only inside the assertion: {body}"
        );
        assert!(
            !body.contains("client_secret"),
            "the assertion kind carries no shared secret: {body}"
        );
    }
}

/// The orthogonal outbound TLS resolves the trust profile's bundle file
/// into platform material, or refuses value-free.
mod outbound_tls {
    use super::*;
    use registry_adapter::auth::{EndpointTls, TlsFault};
    use registry_adapter_core::AdapterRuntimeConfig;
    use registry_platform_yaml::LocalId;

    /// Throwaway self-signed fixtures generated for these tests only; no
    /// deployment has ever trusted them.
    const ROOT_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBnzCCAUWgAwIBAgIUGSkZVSD93tTafMYk9zXkW+9N+VcwCgYIKoZIzj0EAwIw\nJTEjMCEGA1UEAwwaUmVnaXN0cnkgQWRhcHRlciBUZXN0IFJvb3QwHhcNMjYxMDMw\nMDQ1NDIwWhcNMzYxMDI3MDQ1NDIwWjAlMSMwIQYDVQQDDBpSZWdpc3RyeSBBZGFw\ndGVyIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIDV7zIjqChx\n97aw2DaQUGi02tuThFuNl5IKP4RFr+5lxRclqsvlNfhU0Y4JnNLDuxdToqXgVKz6\nDnA2hpkMqZyjUzBRMB0GA1UdDgQWBBSPV2C1/cYwPYf/YYcSqJMvbWT8OjAfBgNV\nHSMEGDAWgBSPV2C1/cYwPYf/YYcSqJMvbWT8OjAPBgNVHRMBAf8EBTADAQH/MAoG\nCCqGSM49BAMCA0gAMEUCIQDE6ceiEQLBfR3wcAbPoXkClwMWZCs+QRHpi9asKR6w\nGwIgG/WsmuvsVVNeDynYVj92+B5SNtyVRK2+p3eo97VtmF0=\n-----END CERTIFICATE-----\n";

    /// A unique scratch path for one test's CA bundle file; the test
    /// writes and removes its own file.
    fn bundle_path(name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("registry-adapter-it-tls-{name}-{unique}.pem"))
    }

    /// A runtime config declaring the one trust profile `private-ca` whose
    /// bundle file is `ca_bundle_file`; `None` declares no profiles.
    fn runtime_config(ca_bundle_file: Option<&str>) -> AdapterRuntimeConfig {
        let trust_profiles = ca_bundle_file.map_or_else(
            || r#"{ "trustProfiles": {} }"#.to_owned(),
            |file| {
                format!(
                    r#"{{ "trustProfiles": {{ "private-ca": {{ "caBundleFile": "{file}" }} }} }}"#
                )
            },
        );
        serde_json::from_str(&format!(
            r#"{{
                "id": "case-deployment",
                "endpoints": [],
                "outboundTls": {trust_profiles},
                "allowedPrivateCidrs": ["10.0.0.0/8"],
                "listener": {{ "bind": "127.0.0.1:8080" }},
                "database": {{
                    "runtimeUrlRef": "secret:env/DB_RUNTIME",
                    "migrationUrlRef": "secret:env/DB_MIGRATION"
                }},
                "oidc": {{
                    "issuer": "https://issuer.example.invalid",
                    "audience": "case-api"
                }},
                "audit": {{ "retentionDays": 90 }}
            }}"#
        ))
        .expect("runtime config")
    }

    /// A binding without a trust profile resolves nothing; a declared
    /// profile's bundle file resolves into both materials whose
    /// rendering carries no PEM; an undeclared profile refuses
    /// value-free.
    #[test]
    fn trust_material_resolves_or_refuses_value_free() {
        let plain = EndpointTls::resolve(
            &binding("https://cases.example.invalid", None),
            &runtime_config(None),
            &resolver(),
        )
        .expect("an unconfigured binding resolves");
        assert!(!plain.is_configured());
        let plain_materials = plain.into_materials();
        assert!(plain_materials.data.is_none());
        assert!(plain_materials.token.is_none());

        let path = bundle_path("root");
        std::fs::write(&path, ROOT_CERTIFICATE_PEM).expect("write bundle");
        let runtime = runtime_config(Some(path.to_str().expect("utf-8 path")));
        let mut tls_binding = binding("https://cases.example.invalid", None);
        tls_binding.tls_trust_profile = Some(LocalId::new("private-ca").expect("local id"));
        let tls =
            EndpointTls::resolve(&tls_binding, &runtime, &resolver()).expect("the bundle resolves");
        std::fs::remove_file(&path).expect("remove bundle");
        assert!(tls.is_configured());
        // The rendering states the material shape and nothing else: the
        // positive half pins what Debug shows, the negative half pins
        // that the PEM is not part of it.
        let rendered = format!("{tls:?}");
        assert!(
            rendered.contains("configured_root_count: 1")
                && rendered.contains("client_identity: false"),
            "the rendering reports the material shape: {rendered}"
        );
        assert!(
            !rendered.contains("BEGIN CERTIFICATE"),
            "the rendering never carries the PEM: {rendered}"
        );
        let materials = tls.into_materials();
        assert!(materials.data.is_some());
        assert!(materials.token.is_some());

        let fault =
            EndpointTls::resolve(&tls_binding, &runtime_config(None), &resolver()).unwrap_err();
        assert_eq!(fault, AuthError::Tls(TlsFault::CaBundle));
        assert_eq!(
            fault.to_string(),
            "the endpoint's CA bundle could not be resolved",
            "the rendering is fixed text that names no profile"
        );
        assert_eq!(fault.class(), CREDENTIAL_REJECTED_CLASS);

        let garbage = bundle_path("garbage");
        std::fs::write(&garbage, "not a pem bundle").expect("write garbage bundle");
        let garbage_runtime = runtime_config(Some(garbage.to_str().expect("utf-8 path")));
        let fault = EndpointTls::resolve(&tls_binding, &garbage_runtime, &resolver()).unwrap_err();
        std::fs::remove_file(&garbage).expect("remove garbage bundle");
        assert_eq!(fault, AuthError::Tls(TlsFault::Material));
        assert_eq!(fault.class(), "egress.refused");
        assert_eq!(
            fault.to_string(),
            "the endpoint's outbound TLS material is not usable",
            "the rendering is fixed text that names no path"
        );
    }
}

/// The marker-secret absence test of the security rule: a recognizable
/// secret, issued or resolved by every kind that carries one, appears in
/// no exchange body, header, property, event, or error the layer
/// produces, only in the credential carriage the concept declares.
mod marker_secret_absence {
    use super::*;

    /// Assert the marker is absent from every rendering, naming what was
    /// scanned so a failure says where the marker leaked.
    fn assert_marker_absent(rendered: &[String], what: &str) {
        for value in rendered {
            assert!(
                !value.contains(MARKER_SECRET),
                "the marker leaked into {what}: {value}"
            );
        }
    }

    /// The static kinds: the marker resolves into the header value and
    /// appears in no rendering of it.
    #[tokio::test]
    async fn static_kinds_render_no_marker() {
        std::env::set_var("ADAPTER_MARK_USER", "marker-user");
        std::env::set_var("ADAPTER_MARK_PASS", MARKER_SECRET);
        std::env::set_var("ADAPTER_MARK_TOKEN", MARKER_SECRET);
        std::env::set_var("ADAPTER_MARK_KEY", MARKER_SECRET);

        let double = UpstreamDouble::start();
        let cases: Vec<(&str, EndpointAuthentication, RuntimeCredential)> = vec![
            (
                "basic",
                EndpointAuthentication::Basic {},
                RuntimeCredential::Basic {
                    username_ref: secret("ADAPTER_MARK_USER"),
                    password_ref: secret("ADAPTER_MARK_PASS"),
                },
            ),
            (
                "static-authorization",
                EndpointAuthentication::StaticAuthorization { scheme: None },
                RuntimeCredential::StaticAuthorization {
                    token_ref: secret("ADAPTER_MARK_TOKEN"),
                },
            ),
            (
                "static-api-key",
                EndpointAuthentication::StaticApiKey {
                    header_name: "X-Api-Key".to_owned(),
                },
                RuntimeCredential::StaticApiKey {
                    value_ref: secret("ADAPTER_MARK_KEY"),
                },
            ),
        ];
        for (tag, endpoint, credential) in cases {
            let plan = AuthPlan::compile(
                &endpoint,
                &binding("https://cases.example.invalid", Some(credential)),
            )
            .unwrap_or_else(|fault| panic!("{tag} must compile: {fault}"));
            let mut events = Vec::new();
            let credential = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
                .await
                .unwrap_or_else(|error| panic!("{tag} must resolve: {error}"))
                .expect("a header is sent");
            let value = String::from_utf8_lossy(credential.header.value().as_bytes()).into_owned();
            match tag {
                // The Basic kind carries the marker base64-encoded, so the
                // raw marker appears nowhere at all; the decoded pair is
                // the exact credential.
                "basic" => {
                    assert!(value.starts_with("Basic "), "{value}");
                    let pair = base64_decode(value.trim_start_matches("Basic "));
                    assert_eq!(
                        pair,
                        format!("marker-user:{MARKER_SECRET}").into_bytes(),
                        "the exact pair traveled"
                    );
                    assert!(!value.contains(MARKER_SECRET));
                }
                _ => {
                    assert!(
                        value.contains(MARKER_SECRET),
                        "the marker is the credential"
                    );
                }
            }
            assert_marker_absent(
                &[format!("{credential:?}"), format!("{events:?}")],
                &format!("the {tag} kind's renderings"),
            );
            assert_eq!(
                double.request_count(),
                0,
                "the {tag} kind's auth layer sends nothing"
            );
        }
    }

    /// The OAuth2 kinds: the marker is the client secret and the issued
    /// credential both; it appears only in the declared carriage.
    #[tokio::test]
    async fn oauth2_kinds_carry_the_marker_only_in_credential_carriage() {
        std::env::set_var("ADAPTER_MARK_CC_ID", "cid-mark");
        std::env::set_var("ADAPTER_MARK_CC_SECRET", MARKER_SECRET);
        std::env::set_var("ADAPTER_MARK_PKJWT_ID", "cid-mark-pj");
        std::env::set_var("ADAPTER_MARK_PKJWT_KEY", MARKER_SECRET);

        // Both placements of the client-credentials kind.
        for (tag, placement) in [
            ("basic-header", CredentialPlacement::BasicHeader),
            ("form-body", CredentialPlacement::FormBody),
        ] {
            let double = UpstreamDouble::start();
            double.respond_with(vec![Response::json(
                200,
                &format!(
                    r#"{{"access_token":"{MARKER_SECRET}","token_type":"Bearer","expires_in":600}}"#
                ),
            )]);
            let plan = AuthPlan::compile(
                &EndpointAuthentication::Oauth2ClientCredentials {},
                &oauth_binding(
                    &double.url("/token"),
                    "ADAPTER_MARK_CC_ID",
                    "ADAPTER_MARK_CC_SECRET",
                    placement,
                ),
            )
            .unwrap_or_else(|fault| panic!("{tag} must compile: {fault}"));
            let mut events = Vec::new();
            let credential = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
                .await
                .unwrap_or_else(|error| panic!("{tag} must issue: {error}"))
                .expect("a header is sent");
            assert_eq!(
                credential.header.value().as_bytes(),
                format!("Bearer {MARKER_SECRET}").as_bytes(),
                "the issued credential is the bearer"
            );

            let request = &double.requests()[0];
            let authorization = request.header("authorization").unwrap_or_default();
            let body = request.body_text();
            let target = request.target.clone();
            let method = request.method.clone();
            match placement {
                CredentialPlacement::BasicHeader => {
                    assert!(authorization.starts_with("Basic "), "{authorization}");
                    let pair = base64_decode(authorization.trim_start_matches("Basic "));
                    assert_eq!(pair, format!("cid-mark:{MARKER_SECRET}").into_bytes());
                    assert!(!authorization.contains(MARKER_SECRET));
                    assert!(
                        !body.contains(MARKER_SECRET),
                        "the body is marker-free: {body}"
                    );
                }
                CredentialPlacement::FormBody => {
                    assert!(
                        authorization.is_empty(),
                        "the form placement has no credential header"
                    );
                    assert_eq!(
                        body.matches(MARKER_SECRET).count(),
                        1,
                        "the marker appears exactly once, in the client_secret member: {body}"
                    );
                    let (before, after) = body
                        .split_once(&format!("client_secret={MARKER_SECRET}"))
                        .expect("the client_secret member carries the marker");
                    assert!(
                        !before.contains(MARKER_SECRET) && !after.contains(MARKER_SECRET),
                        "no other member carries the marker: {body}"
                    );
                }
            }
            let mut scanned = vec![
                format!("{credential:?}"),
                format!("{events:?}"),
                method,
                target,
            ];
            for (name, value) in &request.headers {
                // A header is text on the wire, so scan it as text. The
                // Basic placement's authorization header is base64, which
                // cannot spell the marker; the form placement sends no
                // credential header at all.
                scanned.push(format!("{name}: {value}"));
            }
            assert_marker_absent(
                &scanned,
                &format!("the {tag} placement's non-credential renderings"),
            );
        }

        // The private-key-jwt kind: the marker is the signing key, bound
        // into the assertion and traveling nowhere else.
        let double = UpstreamDouble::start();
        double.respond_with(vec![Response::json(
            200,
            r#"{"access_token":"issued-pj-mark","token_type":"Bearer","expires_in":600}"#,
        )]);
        let token_endpoint = double.url("/token");
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2PrivateKeyJwt {},
            &binding(
                "https://cases.example.invalid",
                Some(RuntimeCredential::Oauth2PrivateKeyJwt {
                    token_endpoint: Url::new(&token_endpoint).expect("url"),
                    client_id_ref: secret("ADAPTER_MARK_PKJWT_ID"),
                    client_assertion_key_ref: secret("ADAPTER_MARK_PKJWT_KEY"),
                    client_assertion_audience: None,
                    scope: None,
                    audience: None,
                    resource: None,
                    maximum_cache_seconds: BoundedU64::new(3600).expect("cache"),
                    assumed_lifetime_seconds: None,
                }),
            ),
        )
        .expect("a usable plan");
        let mut events = Vec::new();
        let credential = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
            .await
            .expect("a credential issues")
            .expect("a header is sent");
        assert_eq!(
            credential.header.value().as_bytes(),
            b"Bearer issued-pj-mark"
        );
        let request = &double.requests()[0];
        let body = request.body_text();
        assert!(
            request.header("authorization").is_none(),
            "no credential header under the assertion kind"
        );
        assert_eq!(
            body.matches(MARKER_SECRET).count(),
            1,
            "the key text appears exactly once, inside the assertion: {body}"
        );
        let before = body
            .strip_suffix(&format!(".{MARKER_SECRET}"))
            .expect("the assertion ends with the bound key");
        assert!(
            before.contains("client_assertion=") && !before.contains(MARKER_SECRET),
            "the marker precedes only the assertion member: {body}"
        );
        assert_marker_absent(
            &[format!("{credential:?}"), format!("{events:?}")],
            "the private-key-jwt renderings",
        );
    }

    /// The fault paths render no marker either: a refusal carries the
    /// registered code, never the server's description of the secret.
    #[tokio::test]
    async fn fault_renderings_carry_no_marker() {
        std::env::set_var("ADAPTER_MARK_FAULT_ID", "cid-fault");
        std::env::set_var("ADAPTER_MARK_FAULT_SECRET", MARKER_SECRET);
        let double = UpstreamDouble::start();
        double.respond_with(vec![Response::refused(
            401,
            "invalid_client",
            &format!("the credential {MARKER_SECRET} was refused"),
        )]);
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &oauth_binding(
                &double.url("/token"),
                "ADAPTER_MARK_FAULT_ID",
                "ADAPTER_MARK_FAULT_SECRET",
                CredentialPlacement::BasicHeader,
            ),
        )
        .expect("a usable plan");
        let mut events = Vec::new();
        let error = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            AuthError::Token(registry_adapter::auth::TokenFault::Refused {
                code: "invalid_client"
            })
        );
        assert_marker_absent(
            &[
                error.to_string(),
                format!("{error:?}"),
                format!("{events:?}"),
            ],
            "the fault renderings",
        );
    }

    /// The marker riding a token endpoint's answer body reaches no
    /// rendering: a 2xx page, an unparseable 2xx body, and an outage's
    /// error page each refuse, and every rendering of the refusal is
    /// fixed text; neither does a marker in the request body survive a
    /// send that never completes on the transport.
    #[tokio::test]
    async fn body_markers_reach_no_rendering() {
        use registry_adapter::auth::TokenFault;
        std::env::set_var("ADAPTER_MARK_BODY_ID", "cid-body");
        std::env::set_var("ADAPTER_MARK_BODY_SECRET", MARKER_SECRET);
        let double = UpstreamDouble::start();
        let cases: [(Response, TokenFault, &'static str); 3] = [
            // A WAF or captive portal answers 200 with the marker in its
            // html: the 2xx carries no usable credential, so it is the
            // credential fault, and the page never surfaces.
            (
                Response {
                    status: 200,
                    media_type: "text/html",
                    body: format!("<html>{MARKER_SECRET} blocked this client</html>"),
                },
                TokenFault::Invalid,
                CREDENTIAL_REJECTED_CLASS,
            ),
            // A 2xx body that is not a JSON object at all is the same
            // credential fault, and the bytes stay unread by any
            // rendering.
            (
                Response {
                    status: 200,
                    media_type: "application/json",
                    body: format!("not a json object, sorry: {MARKER_SECRET}"),
                },
                TokenFault::Invalid,
                CREDENTIAL_REJECTED_CLASS,
            ),
            // An outage's error page answers 503 with the marker on it:
            // unavailable, catchable and retryable, and the page stays
            // off the record.
            (
                Response {
                    status: 503,
                    media_type: "text/html",
                    body: format!("<html>upstream down {MARKER_SECRET}</html>"),
                },
                TokenFault::Unavailable { status: 503 },
                "upstream.http",
            ),
        ];
        for (response, fault, class) in cases {
            double.respond_with(vec![response]);
            let plan = AuthPlan::compile(
                &EndpointAuthentication::Oauth2ClientCredentials {},
                &oauth_binding(
                    &double.url("/token"),
                    "ADAPTER_MARK_BODY_ID",
                    "ADAPTER_MARK_BODY_SECRET",
                    CredentialPlacement::BasicHeader,
                ),
            )
            .expect("a usable plan");
            let mut events = Vec::new();
            let error = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
                .await
                .unwrap_err();
            assert_eq!(error, AuthError::Token(fault));
            assert_eq!(error.class(), class);
            assert_marker_absent(
                &[
                    error.to_string(),
                    format!("{error:?}"),
                    format!("{events:?}"),
                ],
                &format!("the {fault:?} renderings"),
            );
        }

        // A send that never completes on the transport: the request body
        // carried the marker to a destination that refuses the
        // connection, and the refusal's renderings are the fixed
        // transport text alone.
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &oauth_binding(
                "http://127.0.0.1:1/token",
                "ADAPTER_MARK_BODY_ID",
                "ADAPTER_MARK_BODY_SECRET",
                CredentialPlacement::BasicHeader,
            ),
        )
        .expect("a usable plan");
        let mut events = Vec::new();
        let error = authorize_with_plan(&plan, &LoopbackSend::new(), &mut events)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            AuthError::Token(TokenFault::Transport {
                kind: registry_platform_httputil::TransportKind::Connect
            }),
            "a closed loopback port refuses the connection"
        );
        assert_eq!(error.class(), "upstream.connection");
        assert_marker_absent(
            &[
                error.to_string(),
                format!("{error:?}"),
                format!("{events:?}"),
            ],
            "the transport renderings",
        );
    }
}
