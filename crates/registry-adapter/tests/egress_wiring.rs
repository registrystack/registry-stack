// SPDX-License-Identifier: Apache-2.0

//! The deployment's outbound egress state, exercised over a real
//! loopback HTTP double: one compiled auth plan per endpoint binding is
//! held from startup, a data send carries the exchange's selected
//! headers with the credential injected after them, an OAuth2 kind
//! acquires its bearer credential through the endpoint's own frozen
//! token transport over the same loopback, and every transport failure
//! inside an admitted exchange lands on its reviewed catchable class
//! while every boundary refusal stays the uncatchable `egress.refused`
//! (`products/adapter/CONCEPT.md` sections 8.11 and 10.2).

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

use registry_adapter::auth::{
    AuthError, AuthEvent, AuthPlanFault, ClientAssertion, ClientAssertionSigner, ProtectedText,
    TokenBudget,
};
use registry_adapter::egress::{
    Egress, EgressError, EgressFault, EgressRefusal, OkStatusCodeRanges, SendBody, SendBodyFormat,
    SendShape,
};
use registry_adapter_core::{
    ComponentKind, CredentialPlacement, Endpoint, EndpointAuthentication, EndpointBinding,
    ErrorClass, RuntimeCredential, MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS,
};
use registry_platform_config::SecretResolver;
use registry_platform_yaml::{
    BoundedU64, ExternalId, LocalId, SecretProvider, SecretReference, UniqueList, Url,
};
use upstream::{Response, UpstreamDouble};

/// A signer that returns a bound assertion, the way the engine's real
/// signer will; the client-credentials kinds never call it.
struct TestSigner;

impl ClientAssertionSigner for TestSigner {
    fn sign_client_assertion(
        &self,
        request: ClientAssertion<'_>,
    ) -> Result<ProtectedText, AuthError> {
        Ok(ProtectedText::from_str_value(&format!(
            "assertion.{}.{}",
            request.client_id, request.audience
        )))
    }
}

fn secret(name: &str) -> SecretReference {
    SecretReference::new(format!("secret:env/{name}")).expect("secret reference")
}

fn resolver() -> SecretResolver {
    SecretResolver::new([SecretProvider::Environment], "").expect("resolver")
}

/// One `http` pack endpoint with the declared authentication and
/// request-header allowlist.
fn pack_endpoint(
    id: &str,
    authentication: EndpointAuthentication,
    request_headers: &[&str],
) -> Endpoint {
    Endpoint {
        id: LocalId::new(id).expect("endpoint id"),
        component: ComponentKind::Http,
        authentication,
        attempt_timeout_milliseconds: BoundedU64::new(10_000).expect("attempt timeout"),
        maximum_response_bytes: BoundedU64::new(1_048_576).expect("response bound"),
        response_headers: UniqueList::new(Vec::new()).expect("response headers"),
        request_headers: UniqueList::new(
            request_headers
                .iter()
                .map(|name| ExternalId::new(*name).expect("header name"))
                .collect::<Vec<_>>(),
        )
        .expect("request headers"),
        operations: Vec::new(),
        tested_versions: Vec::new(),
        query_file: None,
        operation_name: None,
        variables: None,
    }
}

/// The runtime config for the given bindings, every origin loopback so
/// the development profile admits it.
fn runtime_config(bindings: Vec<EndpointBinding>) -> registry_adapter_core::AdapterRuntimeConfig {
    runtime_config_with(bindings, &["192.168.0.0/16"], None)
}

/// The runtime config with the declared private-CIDR allowlist and
/// outbound TLS. `tls` is the `outboundTls` object, `None` for the
/// default deployments that trust only the system roots.
fn runtime_config_with(
    bindings: Vec<EndpointBinding>,
    cidrs: &[&str],
    tls: Option<registry_adapter_core::OutboundTls>,
) -> registry_adapter_core::AdapterRuntimeConfig {
    registry_adapter_core::AdapterRuntimeConfig {
        id: LocalId::new("egress-deployment").expect("deployment id"),
        endpoints: registry_platform_yaml::UniqueIdList::new(bindings).expect("bindings"),
        allowed_private_cidrs: UniqueList::new(
            cidrs
                .iter()
                .map(|cidr| registry_adapter_core::Cidr::new(cidr).expect("cidr"))
                .collect::<Vec<_>>(),
        )
        .expect("cidrs"),
        outbound_tls: tls,
        listener: serde_json::from_str(r#"{ "bind": "127.0.0.1:8080" }"#).expect("listener"),
        database: serde_json::from_str(
            r#"{
                "runtimeUrlRef": "secret:env/EGR_C4B_DB_RUNTIME",
                "migrationUrlRef": "secret:env/EGR_C4B_DB_MIGRATION"
            }"#,
        )
        .expect("database"),
        oidc: serde_json::from_str(
            r#"{ "issuer": "https://issuer.example.invalid", "audience": "egress" }"#,
        )
        .expect("oidc"),
        allowed_clients: UniqueList::new(vec![ExternalId::new("egress-client").expect("client")])
            .expect("clients"),
        audit: registry_adapter_core::AuditRetention {
            retention_days: registry_platform_yaml::BoundedU32::<1, 3_650>::new(90)
                .expect("retention"),
        },
        cursor_key_ref: None,
        previous_cursor_key_ref: None,
        cursor_ttl_seconds: None,
        idempotency: None,
    }
}

fn oauth_binding(
    endpoint: &str,
    base_url: &str,
    token_endpoint: &str,
    client_id_env: &str,
    client_secret_env: &str,
) -> EndpointBinding {
    EndpointBinding {
        endpoint: ExternalId::new(endpoint).expect("endpoint id"),
        base_url: Url::new(base_url).expect("base url"),
        credential: Some(RuntimeCredential::Oauth2ClientCredentials {
            token_endpoint: Url::new(token_endpoint).expect("token endpoint"),
            client_id_ref: secret(client_id_env),
            client_secret_ref: secret(client_secret_env),
            scope: None,
            audience: None,
            resource: None,
            credential_placement: CredentialPlacement::BasicHeader,
            maximum_cache_seconds: BoundedU64::<0, 86_400>::new(3600).expect("cache ceiling"),
            assumed_lifetime_seconds: None,
        }),
        tls_trust_profile: None,
        mtls_identity: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
    }
}

fn basic_binding(
    endpoint: &str,
    base_url: &str,
    user_env: &str,
    password_env: &str,
) -> EndpointBinding {
    EndpointBinding {
        endpoint: ExternalId::new(endpoint).expect("endpoint id"),
        base_url: Url::new(base_url).expect("base url"),
        credential: Some(RuntimeCredential::Basic {
            username_ref: secret(user_env),
            password_ref: secret(password_env),
        }),
        tls_trust_profile: None,
        mtls_identity: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
    }
}

fn static_api_key_binding(endpoint: &str, base_url: &str, value_env: &str) -> EndpointBinding {
    EndpointBinding {
        endpoint: ExternalId::new(endpoint).expect("endpoint id"),
        base_url: Url::new(base_url).expect("base url"),
        credential: Some(RuntimeCredential::StaticApiKey {
            value_ref: secret(value_env),
        }),
        tls_trust_profile: None,
        mtls_identity: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
    }
}

/// The attempt timeout and response bound every send in this file
/// carries, until the pack's endpoint keys land.
const ATTEMPT: std::time::Duration = std::time::Duration::from_secs(10);
const MAXIMUM_RESPONSE_BYTES: usize = 64 * 1024;

async fn authorize(
    egress: &Egress,
    endpoint: &str,
    budget: &mut TokenBudget,
    events: &mut Vec<AuthEvent>,
) -> Result<Option<registry_adapter::auth::AuthorizedCredential>, AuthError> {
    let bound = egress
        .endpoint(endpoint)
        .expect("the endpoint compiled at startup");
    bound
        .authorize(budget, &resolver(), &TestSigner, events)
        .await
}

/// One GET send under the reviewed 200-299 range, the shape the
/// response-classification tests below vary: the attempt deadline and
/// the throw option are the knobs under test.
fn outbound<'a>(
    link: &'a str,
    authorization: &'a registry_adapter::auth::AuthHeader,
    attempt: std::time::Duration,
    throw: bool,
) -> registry_adapter::egress::OutboundSend<'a> {
    registry_adapter::egress::OutboundSend {
        link,
        exchange_headers: &[],
        shape: SendShape::Get,
        authorization: Some(authorization),
        attempt,
        maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
        ok_status_ranges: OkStatusCodeRanges::default(),
        throw_exception_on_failure: throw,
    }
}

/// The upstream failure an admitted exchange ended on.
fn upstream_failure(error: &EgressError) -> &registry_adapter::egress::UpstreamFailure {
    match error {
        EgressError::Upstream(failure) => failure,
        EgressError::Refused(refusal) => panic!("not a refusal case: {refusal:?}"),
    }
}

/// The deployment holds exactly one compiled auth plan per bound
/// endpoint from startup, and loading sends nothing: the loopback
/// double sees no request until an exchange sends one.
#[tokio::test]
async fn startup_compiles_one_plan_per_endpoint_and_sends_nothing() {
    std::env::set_var("EGR_C4B_ONE_USER", "one-user");
    std::env::set_var("EGR_C4B_ONE_PASSWORD", "one-password");
    std::env::set_var("EGR_C4B_TWO_USER", "two-user");
    std::env::set_var("EGR_C4B_TWO_PASSWORD", "two-password");
    let upstream = UpstreamDouble::start();
    let config = runtime_config(vec![
        basic_binding(
            "cases-api",
            &upstream.url("/"),
            "EGR_C4B_ONE_USER",
            "EGR_C4B_ONE_PASSWORD",
        ),
        basic_binding(
            "files-api",
            &upstream.url("/"),
            "EGR_C4B_TWO_USER",
            "EGR_C4B_TWO_PASSWORD",
        ),
    ]);
    let endpoints = vec![
        pack_endpoint("cases-api", EndpointAuthentication::Basic {}, &[]),
        pack_endpoint("files-api", EndpointAuthentication::Basic {}, &[]),
    ];

    let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");

    assert_eq!(egress.len(), 2, "one entry per bound endpoint");
    assert!(
        egress.endpoint("cases-api").is_some() && egress.endpoint("files-api").is_some(),
        "each bound endpoint carries its compiled state"
    );
    assert_eq!(
        upstream.request_count(),
        0,
        "compiling the plans sends no request"
    );
}

/// An OAuth2 client-credentials kind acquires its bearer credential
/// through the endpoint's own frozen token transport, over a real
/// loopback exchange: the token request is the reviewed shape (the
/// Basic pair in the authorization slot, the grant alone in the body,
/// the client secret never repeated as a body member), the issued
/// credential is cached and carried on the data send, and no
/// credential value enters the journal events.
#[tokio::test]
async fn an_oauth2_kind_acquires_and_carries_a_token_over_the_frozen_transport() {
    std::env::set_var("EGR_C4B_WIRE_ID", "wire-client");
    std::env::set_var("EGR_C4B_WIRE_SECRET", "wire-secret");
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        // The token endpoint's answer, then the data send's reply.
        Response::json(
            200,
            r#"{"access_token":"egress-token-1","token_type":"Bearer","expires_in":3600}"#,
        ),
        Response::json(200, r#"{"ok":true}"#),
    ]);
    let config = runtime_config(vec![oauth_binding(
        "cases-api",
        &upstream.url("/"),
        &upstream.url("/token"),
        "EGR_C4B_WIRE_ID",
        "EGR_C4B_WIRE_SECRET",
    )]);
    let endpoints = vec![pack_endpoint(
        "cases-api",
        EndpointAuthentication::Oauth2ClientCredentials {},
        &[],
    )];
    let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");
    let bound = egress.endpoint("cases-api").expect("the endpoint");

    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let credential = authorize(&egress, "cases-api", &mut budget, &mut events)
        .await
        .expect("the token acquisition completes through the frozen transport");
    let credential = credential.expect("an oauth2 kind produces a header").header;

    // The token request is the reviewed client-credentials shape. The
    // double records values; the assertions here read them only to
    // prove placement, never into a journal or diagnostic.
    let token_request = &upstream.requests()[0];
    assert_eq!(token_request.method, "POST");
    assert_eq!(token_request.target, "/token");
    assert_eq!(
        token_request.header("authorization"),
        // base64("wire-client:wire-secret"), the pair in the Basic slot.
        Some("Basic d2lyZS1jbGllbnQ6d2lyZS1zZWNyZXQ="),
        "the Basic pair rides the token request's authorization slot"
    );
    let token_body = String::from_utf8(token_request.body.clone()).expect("form body");
    assert!(
        token_body.contains("grant_type=client_credentials"),
        "the body carries the grant: {token_body}"
    );
    assert!(
        !token_body.contains("client_id")
            && !token_body.contains("client_secret")
            && !token_body.contains("wire-secret"),
        "the Basic placement never repeats the pair in the body: {token_body}"
    );

    // The data send carries the issued credential, not the client
    // pair.
    let reply = bound
        .send(registry_adapter::egress::OutboundSend {
            link: &upstream.url("/records"),
            exchange_headers: &[],
            shape: SendShape::Get,
            authorization: Some(&credential),
            attempt: ATTEMPT,
            maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            ok_status_ranges: OkStatusCodeRanges::default(),
            throw_exception_on_failure: true,
        })
        .await
        .expect("the admitted send completes");
    assert_eq!(reply.status, 200);
    let data_request = &upstream.requests()[1];
    assert_eq!(
        data_request.header("authorization"),
        Some("Bearer egress-token-1"),
        "the issued credential rides the data send"
    );

    // The journal events name the outcomes, never a value.
    let rendered = format!("{events:?}");
    assert!(
        !rendered.contains("egress-token-1")
            && !rendered.contains("wire-secret")
            && !rendered.contains("wire-client"),
        "the journal events carry no credential value: {rendered}"
    );
}

/// The signed-assertion kind acquires its credential through the same
/// frozen transport with no authorization header at all: the client id
/// and the signed assertion ride the reviewed form body, and the
/// assertion the signer produced is the assertion the wire carries.
#[tokio::test]
async fn a_private_key_jwt_kind_posts_its_assertion_without_an_authorization_header() {
    std::env::set_var("EGR_C4B_PKJWT_ID", "pkjwt-client");
    std::env::set_var("EGR_C4B_PKJWT_KEY", "pkjwt-key-material");
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        200,
        r#"{"access_token":"pkjwt-token-1","token_type":"Bearer","expires_in":3600}"#,
    )]);
    let config = runtime_config(vec![{
        let mut binding = oauth_binding(
            "pkjwt-api",
            &upstream.url("/"),
            &upstream.url("/token"),
            "EGR_C4B_PKJWT_ID",
            "EGR_C4B_PKJWT_KEY",
        );
        binding.credential = Some(RuntimeCredential::Oauth2PrivateKeyJwt {
            token_endpoint: registry_platform_yaml::Url::new(upstream.url("/token"))
                .expect("token endpoint"),
            client_id_ref: secret("EGR_C4B_PKJWT_ID"),
            client_assertion_key_ref: secret("EGR_C4B_PKJWT_KEY"),
            client_assertion_audience: None,
            scope: None,
            audience: None,
            resource: None,
            maximum_cache_seconds: BoundedU64::<0, 86_400>::new(3600).expect("cache ceiling"),
            assumed_lifetime_seconds: None,
        });
        binding
    }]);
    let endpoints = vec![pack_endpoint(
        "pkjwt-api",
        EndpointAuthentication::Oauth2PrivateKeyJwt {},
        &[],
    )];
    let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");

    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let credential = authorize(&egress, "pkjwt-api", &mut budget, &mut events)
        .await
        .expect("the assertion acquisition completes through the frozen transport");
    let credential = credential
        .expect("a signed-assertion kind produces a header")
        .header;

    let token_request = &upstream.requests()[0];
    assert_eq!(token_request.method, "POST");
    assert_eq!(token_request.target, "/token");
    assert!(
        token_request.header("authorization").is_none(),
        "the assertion kind authenticates in the body alone"
    );
    let token_body = String::from_utf8(token_request.body.clone()).expect("form body");
    assert!(
        token_body.contains("grant_type=client_credentials")
            && token_body.contains("client_id=pkjwt-client")
            && token_body.contains(
                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
            )
            && token_body
                .contains("client_assertion=assertion.pkjwt-client.http%3A%2F%2F127.0.0.1"),
        "the body carries the client id and the signed assertion: {token_body}"
    );
    assert!(
        !token_body.contains("client_secret"),
        "no secret rides the assertion kind's body: {token_body}"
    );
    let rendered = format!("{events:?}");
    assert!(
        !rendered.contains("pkjwt-token-1") && !rendered.contains("pkjwt-key-material"),
        "the journal events carry no credential value: {rendered}"
    );
    assert_eq!(
        credential.value().as_bytes(),
        b"pkjwt-token-1",
        "the issued credential is the raw access token; the data template applies Bearer"
    );
}

/// A destination the address policy refuses raises the uncatchable
/// `egress.refused`, and no byte reaches the network.
#[tokio::test]
async fn a_refused_destination_surfaces_as_egress_refused() {
    std::env::set_var("EGR_C4B_PRIVATE_USER", "private-user");
    std::env::set_var("EGR_C4B_PRIVATE_PASSWORD", "private-password");
    let config = runtime_config(vec![basic_binding(
        "private-api",
        "http://10.0.0.7:8080/",
        "EGR_C4B_PRIVATE_USER",
        "EGR_C4B_PRIVATE_PASSWORD",
    )]);
    let endpoints = vec![pack_endpoint(
        "private-api",
        EndpointAuthentication::Basic {},
        &[],
    )];
    let egress = Egress::load(&endpoints, &config, &resolver())
        .expect("the binding loads; the allowlist refuses at send time");

    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let credential = authorize(&egress, "private-api", &mut budget, &mut events)
        .await
        .expect("a basic kind resolves its pair");
    let credential = credential.expect("a basic kind produces a header").header;

    // 10.0.0.7 is a private literal outside 192.168.0.0/16, the only
    // private range this deployment admits.
    let bound = egress.endpoint("private-api").expect("the endpoint");
    let error = bound
        .send(registry_adapter::egress::OutboundSend {
            link: "http://10.0.0.7:8080/records",
            exchange_headers: &[],
            shape: SendShape::Get,
            authorization: Some(&credential),
            attempt: ATTEMPT,
            maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            ok_status_ranges: OkStatusCodeRanges::default(),
            throw_exception_on_failure: true,
        })
        .await
        .expect_err("the policy refuses the private address");

    match &error {
        EgressError::Refused(EgressRefusal::Destination {
            fault,
            journal_name,
        }) => {
            assert_eq!(
                error.class(),
                ErrorClass::EgressRefused,
                "the refusal is the uncatchable class"
            );
            assert!(
                matches!(
                    fault,
                    registry_platform_httputil::destination::DestinationSendError::PrivateAddressNotAllowed
                ),
                "the private address outside the allowlist is refused: {fault:?}"
            );
            assert_eq!(
                *journal_name, "private-address-not-allowed",
                "the refusal carries its static journal name"
            );
        }
        EgressError::Refused(refusal) => {
            panic!("the send reached another refusal first: {refusal:?}")
        }
        EgressError::Upstream(failure) => {
            panic!("the refusal is not an upstream answer: {failure:?}")
        }
    }
    let rendered = error.to_string();
    assert!(
        !rendered.contains("private-user") && !rendered.contains("private-password"),
        "the refusal never carries a credential: {rendered}"
    );
}

/// The credential is injected after the exchange's selected headers:
/// both travel, the credential cannot be shadowed by an exchange
/// header, and the `authorization` name is never allowlistable.
#[tokio::test]
async fn the_credential_travels_after_the_exchange_headers() {
    std::env::set_var("EGR_C4B_WIRE_USER", "wire-user");
    std::env::set_var("EGR_C4B_WIRE_PASSWORD", "wire-pass");
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(200, r#"{"ok":true}"#)]);
    let config = runtime_config(vec![basic_binding(
        "wire-api",
        &upstream.url("/"),
        "EGR_C4B_WIRE_USER",
        "EGR_C4B_WIRE_PASSWORD",
    )]);
    let endpoints = vec![pack_endpoint(
        "wire-api",
        EndpointAuthentication::Basic {},
        &["x-trace"],
    )];
    let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");
    let bound = egress.endpoint("wire-api").expect("the endpoint");

    // An exchange that also holds an `authorization` entry in both
    // cases: the allowlist cannot contain a reserved name, so neither
    // spelling is ever selected and the credential the plan produced
    // travels alone in the injected slot.
    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let credential = authorize(&egress, "wire-api", &mut budget, &mut events)
        .await
        .expect("a basic kind resolves its pair");
    let credential = credential.expect("a basic kind produces a header").header;

    let reply = bound
        .send(registry_adapter::egress::OutboundSend {
            link: &upstream.url("/records"),
            exchange_headers: &[
                ("authorization".to_owned(), "shadow-payload".to_owned()),
                ("Authorization".to_owned(), "shadow-upper".to_owned()),
                ("x-trace".to_owned(), "trace-1".to_owned()),
            ],
            shape: SendShape::Get,
            authorization: Some(&credential),
            attempt: ATTEMPT,
            maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            ok_status_ranges: OkStatusCodeRanges::default(),
            throw_exception_on_failure: true,
        })
        .await
        .expect("the send completes");

    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, serde_json::json!({ "ok": true }));

    let recorded = &upstream.requests()[0];
    assert_eq!(
        recorded.header("x-trace"),
        Some("trace-1"),
        "the selected exchange header travels"
    );
    assert_eq!(
        recorded.header("authorization"),
        // base64("wire-user:wire-pass")
        Some("Basic d2lyZS11c2VyOndpcmUtcGFzcw=="),
        "the credential travels, not any exchange entry"
    );
    let authorization_count = recorded
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .count();
    assert_eq!(
        authorization_count, 1,
        "the credential appears exactly once"
    );
    let rendered: Vec<String> = recorded
        .headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect();
    let rendered = rendered.join("\n");
    assert!(
        !rendered.contains("shadow-payload") && !rendered.contains("shadow-upper"),
        "no exchange entry under a reserved name reaches the wire: {rendered}"
    );
}

/// An api-key endpoint's declared header is likewise never
/// allowlistable: an exchange entry under that exact name, and one
/// under `Authorization`, is dropped, the resolved key travels alone in
/// its declared slot, and an unreserved listed name travels beside it.
#[tokio::test]
async fn an_exchange_entry_under_the_api_key_name_never_shadows_the_key() {
    std::env::set_var("EGR_C4B_KEY_VALUE", "key-777");
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(200, r#"{"stored":true}"#)]);
    let config = runtime_config(vec![static_api_key_binding(
        "key-api",
        &upstream.url("/"),
        "EGR_C4B_KEY_VALUE",
    )]);
    let endpoints = vec![pack_endpoint(
        "key-api",
        EndpointAuthentication::StaticApiKey {
            header_name: "x-api-key".to_owned(),
        },
        &["x-api-trace"],
    )];
    let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");
    let bound = egress.endpoint("key-api").expect("the endpoint");

    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let credential = authorize(&egress, "key-api", &mut budget, &mut events)
        .await
        .expect("a static api key resolves its value");
    let credential = credential.expect("an api key produces a header").header;

    bound
        .send(registry_adapter::egress::OutboundSend {
            link: &upstream.url("/records"),
            exchange_headers: &[
                ("x-api-key".to_owned(), "shadow-key".to_owned()),
                ("Authorization".to_owned(), "shadow-auth".to_owned()),
                ("x-api-trace".to_owned(), "trace-2".to_owned()),
            ],
            shape: SendShape::Get,
            authorization: Some(&credential),
            attempt: ATTEMPT,
            maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            ok_status_ranges: OkStatusCodeRanges::default(),
            throw_exception_on_failure: true,
        })
        .await
        .expect("the send completes");

    let recorded = &upstream.requests()[0];
    assert_eq!(
        recorded.header("x-api-key"),
        Some("key-777"),
        "the resolved key travels, not any exchange entry"
    );
    assert!(
        recorded.header("authorization").is_none(),
        "an api-key send injects no authorization header"
    );
    assert_eq!(
        recorded.header("x-api-trace"),
        Some("trace-2"),
        "the listed unreserved exchange header travels beside the key"
    );
}

/// A redirect is never followed, whatever its spelling: every 3xx
/// answer raises `upstream.redirect` carrying its status, and the
/// double sees exactly one request. Camel's disabled-redirect test also
/// exposes the 3xx through `HttpOperationFailedException`
/// (`camel-4.23.0:components/camel-http/src/test/java/org/apache/camel/component/http/HttpRedirectTest.java#httpRedirectFalse`).
/// Refusing every redirect and retaining no `Location` value is the Adapter's
/// security divergence from
/// <https://camel.apache.org/components/4.23.x/http-component.html>.
#[tokio::test]
async fn a_redirect_is_raised_and_never_followed() {
    for status in [301, 302, 303, 307, 308] {
        std::env::set_var("EGR_C4B_REDIR_USER", "redirect-user");
        std::env::set_var("EGR_C4B_REDIR_PASSWORD", "redirect-pass");
        let upstream = UpstreamDouble::start();
        upstream.respond_with(vec![upstream::Response {
            status,
            media_type: "text/plain",
            body: String::new(),
        }]);
        let config = runtime_config(vec![basic_binding(
            "redirect-api",
            &upstream.url("/"),
            "EGR_C4B_REDIR_USER",
            "EGR_C4B_REDIR_PASSWORD",
        )]);
        let endpoints = vec![pack_endpoint(
            "redirect-api",
            EndpointAuthentication::Basic {},
            &[],
        )];
        let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");
        let bound = egress.endpoint("redirect-api").expect("the endpoint");

        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let credential = authorize(&egress, "redirect-api", &mut budget, &mut events)
            .await
            .expect("a basic kind resolves its pair");
        let credential = credential.expect("a basic kind produces a header").header;

        let error = bound
            .send(registry_adapter::egress::OutboundSend {
                link: &upstream.url("/records"),
                exchange_headers: &[],
                shape: SendShape::Get,
                authorization: Some(&credential),
                attempt: ATTEMPT,
                maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
                ok_status_ranges: OkStatusCodeRanges::try_from_ranges(vec![(200, 399)])
                    .expect("the redirect-covering status range is valid"),
                throw_exception_on_failure: true,
            })
            .await
            .expect_err("a 3xx is a redirect failure");

        let failure = match &error {
            EgressError::Upstream(failure) => failure,
            EgressError::Refused(refusal) => panic!("a 3xx is not a refusal: {refusal:?}"),
        };
        assert_eq!(
            failure.class,
            ErrorClass::UpstreamRedirect,
            "the 3xx raises the redirect class"
        );
        assert_eq!(failure.status, Some(status));
        assert_eq!(
            upstream.request_count(),
            1,
            "the {status}'s Location is never requested"
        );
    }
}

/// A link outside the pinned origin is refused before any send, and a
/// link inside it travels with its query exactly as written.
#[tokio::test]
async fn the_pinned_origin_refuses_foreign_links_and_sends_the_target_unchanged() {
    std::env::set_var("EGR_C4B_LINK_USER", "link-user");
    std::env::set_var("EGR_C4B_LINK_PASSWORD", "link-pass");
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(200, r#"{"page":1}"#)]);
    let config = runtime_config(vec![basic_binding(
        "link-api",
        &upstream.url("/api"),
        "EGR_C4B_LINK_USER",
        "EGR_C4B_LINK_PASSWORD",
    )]);
    let endpoints = vec![pack_endpoint(
        "link-api",
        EndpointAuthentication::Basic {},
        &[],
    )];
    let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");
    let bound = egress.endpoint("link-api").expect("the endpoint");

    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let credential = authorize(&egress, "link-api", &mut budget, &mut events)
        .await
        .expect("a basic kind resolves its pair");
    let credential = credential.expect("a basic kind produces a header").header;

    // A different port is a different origin: a probe port the double
    // does not hold, free again by the time the pin refuses the link.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
    let foreign_port = probe.local_addr().expect("probe port").port();
    drop(probe);
    let foreign = format!("http://127.0.0.1:{foreign_port}/api/records");
    let error = bound
        .send(registry_adapter::egress::OutboundSend {
            link: &foreign,
            exchange_headers: &[],
            shape: SendShape::Get,
            authorization: Some(&credential),
            attempt: ATTEMPT,
            maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            ok_status_ranges: OkStatusCodeRanges::default(),
            throw_exception_on_failure: true,
        })
        .await
        .expect_err("a foreign origin is refused");
    assert!(
        matches!(error, EgressError::Refused(_)),
        "a foreign origin is a refusal: {error:?}"
    );
    assert_eq!(
        upstream.request_count(),
        0,
        "a refused link never reaches the network"
    );

    // A link under the base path travels as written.
    bound
        .send(registry_adapter::egress::OutboundSend {
            link: &upstream.url("/api/records?page=2&size=5"),
            exchange_headers: &[],
            shape: SendShape::Get,
            authorization: Some(&credential),
            attempt: ATTEMPT,
            maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            ok_status_ranges: OkStatusCodeRanges::default(),
            throw_exception_on_failure: true,
        })
        .await
        .expect("the in-origin link sends");
    let recorded = &upstream.requests()[0];
    assert_eq!(
        recorded.target, "/api/records?page=2&size=5",
        "the query travels exactly as written"
    );
}

/// A token endpoint on plain HTTP over a host that is not loopback
/// refuses the load: core's checks refuse it, and the runtime refuses
/// the same origin, so a deployment that skips the checks cannot start
/// with a client credential rendered in clear (CONCEPT 10.2).
#[test]
fn a_plain_http_non_loopback_token_endpoint_refuses_at_load() {
    std::env::set_var("EGR_C4B_CLEAR_ID", "clear-client");
    std::env::set_var("EGR_C4B_CLEAR_SECRET", "clear-secret");
    let config = runtime_config(vec![oauth_binding(
        "cases-api",
        "http://127.0.0.1:1/",
        "http://10.0.0.5:9/token",
        "EGR_C4B_CLEAR_ID",
        "EGR_C4B_CLEAR_SECRET",
    )]);
    let endpoints = vec![pack_endpoint(
        "cases-api",
        EndpointAuthentication::Oauth2ClientCredentials {},
        &[],
    )];
    let error = match Egress::load(&endpoints, &config, &resolver()) {
        Err(fault) => fault,
        Ok(_) => panic!("a clear-text token endpoint refuses the load"),
    };
    assert!(
        matches!(
            &error,
            EgressFault::Auth(AuthError::Plan(AuthPlanFault::TokenEndpointNotUsable))
        ),
        "the load refuses at the plan's token-origin check: {error:?}"
    );
    let rendered = error.to_string();
    assert!(
        !rendered.contains("clear-secret") && !rendered.contains("clear-client"),
        "the refusal never carries credential material: {rendered}"
    );
}

/// A POST send carries its rendered body under the frozen post
/// template: the body travels with the declared codec's media type, the
/// credential rides the injected slot, and an undecodable reply fails
/// exactly as a GET's would, as maybe-sent.
#[tokio::test]
async fn a_post_send_carries_its_body_and_classifies_its_reply() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![upstream::Response {
        status: 200,
        media_type: "text/html",
        body: "<html>queued</html>".to_owned(),
    }]);
    let (egress, credential) = load_basic_and_authorize(
        &upstream,
        "post-api",
        "EGR_C4B_POST_USER",
        "EGR_C4B_POST_PASSWORD",
        "post-user",
        "post-pass",
    )
    .await;
    let bound = egress.endpoint("post-api").expect("the endpoint");

    let body = br#"{"record": 7}"#;
    let error = bound
        .send(registry_adapter::egress::OutboundSend {
            link: &upstream.url("/records"),
            exchange_headers: &[],
            shape: SendShape::Post(SendBody {
                format: SendBodyFormat::Json,
                bytes: body,
            }),
            authorization: Some(&credential),
            attempt: ATTEMPT,
            maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            ok_status_ranges: OkStatusCodeRanges::default(),
            throw_exception_on_failure: true,
        })
        .await
        .expect_err("the HTML reply is malformed under the throw");

    let failure = upstream_failure(&error);
    assert_eq!(failure.class, ErrorClass::UpstreamMalformed);
    assert_eq!(
        failure.certainty_journal_name(),
        "maybe-sent",
        "the POST was delivered; only the reply was unusable"
    );

    let recorded = &upstream.requests()[0];
    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.body, body.to_vec(), "the rendered body travels");
    assert_eq!(
        recorded.header("authorization"),
        // base64("post-user:post-pass")
        Some("Basic cG9zdC11c2VyOnBvc3QtcGFzcw=="),
        "the credential rides the POST's injected slot"
    );
    let content_type = recorded
        .header("content-type")
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    assert_eq!(
        content_type, "application/json",
        "the codec decides the media type"
    );
}

/// A loaded basic endpoint and its resolved credential, the fixture the
/// reply-classification tests send against.
async fn load_basic_and_authorize(
    upstream: &UpstreamDouble,
    endpoint: &str,
    user_env: &str,
    password_env: &str,
    user: &str,
    password: &str,
) -> (Egress, registry_adapter::auth::AuthHeader) {
    std::env::set_var(user_env, user);
    std::env::set_var(password_env, password);
    let config = runtime_config(vec![basic_binding(
        endpoint,
        &upstream.url("/"),
        user_env,
        password_env,
    )]);
    let endpoints = vec![pack_endpoint(
        endpoint,
        EndpointAuthentication::Basic {},
        &[],
    )];
    let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");
    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let credential = authorize(&egress, endpoint, &mut budget, &mut events)
        .await
        .expect("a basic kind resolves its pair")
        .expect("a basic kind produces a header")
        .header;
    (egress, credential)
}

// Attempt ceiling.

/// An attempt above the platform's one-operation ceiling is refused,
/// never shortened: exactly at the ceiling the send runs, one
/// millisecond above it the send refuses before any byte leaves, so a
/// declared timeout can never silently become another number
/// (CONCEPT 8.8).
#[tokio::test]
async fn an_attempt_above_the_maximum_is_refused_never_shortened() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(200, r#"{"at":"ceiling"}"#),
        Response::json(200, r#"{"never":true}"#),
    ]);
    let (egress, credential) = load_basic_and_authorize(
        &upstream,
        "max-api",
        "EGR_C4B_MAX_USER",
        "EGR_C4B_MAX_PASSWORD",
        "max-user",
        "max-pass",
    )
    .await;
    let bound = egress.endpoint("max-api").expect("the endpoint");

    let at_ceiling = bound
        .send(outbound(
            &upstream.url("/records"),
            &credential,
            std::time::Duration::from_millis(MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS),
            true,
        ))
        .await
        .expect("an attempt exactly at the ceiling runs");
    assert_eq!(at_ceiling.status, 200);

    let error = bound
        .send(outbound(
            &upstream.url("/records"),
            &credential,
            std::time::Duration::from_millis(MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS + 1),
            true,
        ))
        .await
        .expect_err("an attempt above the ceiling refuses");
    match &error {
        EgressError::Refused(EgressRefusal::AttemptAboveMaximum) => {}
        other => panic!("the over-limit attempt refuses as itself: {other:?}"),
    }
    assert_eq!(error.class(), ErrorClass::EgressRefused);
    assert_eq!(
        upstream.request_count(),
        1,
        "the refused send never reaches the network"
    );
}

// Reply bodies.

/// An empty body is JSON null, a successful reply, not a decode
/// failure (CONCEPT 8.11).
#[tokio::test]
async fn an_empty_body_is_json_null() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![upstream::Response {
        status: 200,
        media_type: "application/json",
        body: String::new(),
    }]);
    let (egress, credential) = load_basic_and_authorize(
        &upstream,
        "null-api",
        "EGR_C4B_NULL_USER",
        "EGR_C4B_NULL_PASSWORD",
        "null-user",
        "null-pass",
    )
    .await;
    let bound = egress.endpoint("null-api").expect("the endpoint");
    let reply = bound
        .send(outbound(
            &upstream.url("/records"),
            &credential,
            ATTEMPT,
            true,
        ))
        .await
        .expect("an empty body is not a failure");
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, serde_json::Value::Null);
}

/// A non-JSON body inside the range raises `upstream.malformed`, not a
/// null body the route could read as "no record": an expired session
/// answering its HTML sign-in page must fail the exchange, never
/// masquerade as a successful empty answer (CONCEPT 8.11).
#[tokio::test]
async fn a_non_json_body_raises_malformed_under_the_throw() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![upstream::Response {
        status: 200,
        media_type: "text/html",
        body: "<html>sign-in</html>".to_owned(),
    }]);
    let (egress, credential) = load_basic_and_authorize(
        &upstream,
        "html-api",
        "EGR_C4B_HTML_USER",
        "EGR_C4B_HTML_PASSWORD",
        "html-user",
        "html-pass",
    )
    .await;
    let bound = egress.endpoint("html-api").expect("the endpoint");
    let error = bound
        .send(outbound(
            &upstream.url("/records"),
            &credential,
            ATTEMPT,
            true,
        ))
        .await
        .expect_err("a non-JSON body is a failure");
    let failure = upstream_failure(&error);
    assert_eq!(failure.class, ErrorClass::UpstreamMalformed);
    assert_eq!(failure.status, Some(200));
    assert!(
        failure.body.is_none(),
        "an undecodable body carries no decoded value"
    );
    assert_eq!(
        failure.certainty_journal_name(),
        "maybe-sent",
        "the reply arrived, so the request was delivered"
    );
    let rendered = error.to_string();
    assert!(
        !rendered.contains("sign-in"),
        "the failure rendering never carries upstream content: {rendered}"
    );
}

/// The same refusal without the throw option: a non-JSON body raises
/// `upstream.malformed` also under `throwExceptionOnFailure: false`
/// (CONCEPT 8.11), because a reply the engine cannot decode is never a
/// reply the route can read.
#[tokio::test]
async fn a_non_json_body_raises_malformed_also_without_the_throw() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![upstream::Response {
        status: 200,
        media_type: "text/html",
        body: "<html>sign-in</html>".to_owned(),
    }]);
    let (egress, credential) = load_basic_and_authorize(
        &upstream,
        "html-api",
        "EGR_C4B_HTML_USER",
        "EGR_C4B_HTML_PASSWORD",
        "html-user",
        "html-pass",
    )
    .await;
    let bound = egress.endpoint("html-api").expect("the endpoint");
    let error = bound
        .send(outbound(
            &upstream.url("/records"),
            &credential,
            ATTEMPT,
            false,
        ))
        .await
        .expect_err("a non-JSON body fails with or without the throw");
    assert_eq!(
        upstream_failure(&error).class,
        ErrorClass::UpstreamMalformed
    );
}

/// A body of valid JSON nesting past the script bound is refused
/// structurally, again as `upstream.malformed`: the route never sees a
/// truncated value.
#[tokio::test]
async fn a_body_over_the_script_json_bound_raises_malformed() {
    let upstream = UpstreamDouble::start();
    // Valid JSON, nested past the decoder's depth bound, so the fault
    // is structural, not a syntax error.
    let deep = format!("{}{}", "[".repeat(64), "]".repeat(64));
    upstream.respond_with(vec![upstream::Response {
        status: 200,
        media_type: "application/json",
        body: deep,
    }]);
    let (egress, credential) = load_basic_and_authorize(
        &upstream,
        "deep-api",
        "EGR_C4B_DEEP_USER",
        "EGR_C4B_DEEP_PASSWORD",
        "deep-user",
        "deep-pass",
    )
    .await;
    let bound = egress.endpoint("deep-api").expect("the endpoint");
    let error = bound
        .send(outbound(
            &upstream.url("/records"),
            &credential,
            ATTEMPT,
            true,
        ))
        .await
        .expect_err("an over-bound body is a failure");
    let failure = upstream_failure(&error);
    assert_eq!(failure.class, ErrorClass::UpstreamMalformed);
    assert_eq!(failure.status, Some(200));
    assert!(failure.body.is_none());
}

// Status ranges and the throw option.

/// Camel treats comma-separated status ranges as a sparse union, including
/// singleton entries and holes
/// (`camel-4.23.0:components/camel-http/src/test/java/org/apache/camel/component/http/helper/HttpHelperTest.java#testIsStatusCodeOkComplexRange`;
/// <https://camel.apache.org/components/4.23.x/http-component.html>).
#[tokio::test]
async fn sparse_status_ranges_accept_each_entry_and_reject_a_hole() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![
        Response::json(400, r#"{"entry":400}"#),
        Response::json(404, r#"{"entry":404}"#),
        Response::json(403, r#"{"hole":403}"#),
    ]);
    let (egress, credential) = load_basic_and_authorize(
        &upstream,
        "sparse-api",
        "EGR_C4B_SPARSE_USER",
        "EGR_C4B_SPARSE_PASSWORD",
        "sparse-user",
        "sparse-pass",
    )
    .await;
    let bound = egress.endpoint("sparse-api").expect("the endpoint");
    let ranges = OkStatusCodeRanges::try_from_ranges(vec![(200, 299), (400, 400), (404, 404)])
        .expect("the sparse status set is valid");
    let link = upstream.url("/records");

    for status in [400, 404] {
        let mut send = outbound(&link, &credential, ATTEMPT, true);
        send.ok_status_ranges = ranges.clone();
        let reply = bound.send(send).await.expect("the listed status succeeds");
        assert_eq!(reply.status, status);
    }

    let mut send = outbound(&link, &credential, ATTEMPT, true);
    send.ok_status_ranges = ranges;
    let failure = bound
        .send(send)
        .await
        .expect_err("the hole between singletons remains out of range");
    assert_eq!(upstream_failure(&failure).class, ErrorClass::UpstreamHttp);
    assert_eq!(upstream_failure(&failure).status, Some(403));
}

/// Out of range and undecodable under the throw flag: the send answers
/// `upstream.http` with no decoded body, because the route is ending
/// anyway and the body never decoded. Camel similarly raises for an
/// out-of-range response when `throwExceptionOnFailure` is true
/// (`camel-4.23.0:components/camel-http/src/test/java/org/apache/camel/component/http/HttpThrowExceptionOnFailureTest.java#httpGetWhichReturnsHttp501ShouldThrowAnException`),
/// while the Adapter's bounded JSON-body handling is its documented
/// divergence from
/// <https://camel.apache.org/components/4.23.x/http-component.html>.
#[tokio::test]
async fn an_undecodable_out_of_range_body_raises_http_without_a_body_under_the_throw() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![upstream::Response {
        status: 502,
        media_type: "text/plain",
        body: "Bad Gateway".to_owned(),
    }]);
    let (egress, credential) = load_basic_and_authorize(
        &upstream,
        "gateway-api",
        "EGR_C4B_GATEWAY_USER",
        "EGR_C4B_GATEWAY_PASSWORD",
        "gateway-user",
        "gateway-pass",
    )
    .await;
    let bound = egress.endpoint("gateway-api").expect("the endpoint");
    let error = bound
        .send(outbound(
            &upstream.url("/records"),
            &credential,
            ATTEMPT,
            true,
        ))
        .await
        .expect_err("an out-of-range status fails under the throw");
    let failure = upstream_failure(&error);
    assert_eq!(failure.class, ErrorClass::UpstreamHttp);
    assert_eq!(failure.status, Some(502));
    assert!(
        failure.body.is_none(),
        "the undecodable body rides no decoded value"
    );
}

/// Out of range and decodable under the throw flag: the failure
/// carries the decoded body, so a clause can read the source's error
/// detail, and its status (CONCEPT 8.11). Camel's failure object likewise
/// retains the response body and status
/// (`camel-4.23.0:components/camel-http/src/main/java/org/apache/camel/component/http/HttpProducer.java#populateHttpOperationFailedException`,
/// `camel-4.23.0:components/camel-http/src/test/java/org/apache/camel/component/http/HttpThrowExceptionOnFailureTest.java#httpGetWhichReturnsHttp501ShouldThrowAnException`;
/// <https://camel.apache.org/components/4.23.x/http-component.html>).
#[tokio::test]
async fn a_decodable_out_of_range_body_raises_http_with_the_body_under_the_throw() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(
        502,
        r#"{"error": "downstream said no"}"#,
    )]);
    let (egress, credential) = load_basic_and_authorize(
        &upstream,
        "downstream-api",
        "EGR_C4B_DOWN_USER",
        "EGR_C4B_DOWN_PASSWORD",
        "down-user",
        "down-pass",
    )
    .await;
    let bound = egress.endpoint("downstream-api").expect("the endpoint");
    let error = bound
        .send(outbound(
            &upstream.url("/records"),
            &credential,
            ATTEMPT,
            true,
        ))
        .await
        .expect_err("an out-of-range status fails under the throw");
    let failure = upstream_failure(&error);
    assert_eq!(failure.class, ErrorClass::UpstreamHttp);
    assert_eq!(failure.status, Some(502));
    assert_eq!(
        failure.body,
        Some(serde_json::json!({ "error": "downstream said no" })),
        "the decoded body travels on the failure"
    );
}

/// Without the throw option an out-of-range status is not a failure:
/// the reply returns as it is and the route reads the status itself
/// (CONCEPT 8.11's `throwExceptionOnFailure: false`), matching
/// `camel-4.23.0:components/camel-http/src/test/java/org/apache/camel/component/http/HttpThrowExceptionOnFailureTest.java#httpGetWhichReturnsHttp501`
/// (<https://camel.apache.org/components/4.23.x/http-component.html>).
#[tokio::test]
async fn without_the_throw_an_out_of_range_status_returns_the_reply() {
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![Response::json(502, r#"{"error": "later"}"#)]);
    let (egress, credential) = load_basic_and_authorize(
        &upstream,
        "later-api",
        "EGR_C4B_LATER_USER",
        "EGR_C4B_LATER_PASSWORD",
        "later-user",
        "later-pass",
    )
    .await;
    let bound = egress.endpoint("later-api").expect("the endpoint");
    let reply = bound
        .send(outbound(
            &upstream.url("/records"),
            &credential,
            ATTEMPT,
            false,
        ))
        .await
        .expect("without the throw the route reads the status itself");
    assert_eq!(reply.status, 502);
    assert_eq!(reply.body, serde_json::json!({ "error": "later" }));
}

// Address policy and the declared CIDRs.

/// A plain-HTTP origin whose literal address sits inside a declared
/// private CIDR loads: core's authoring check admits it by the same
/// one rule (D36), the runtime's load agrees, and the send-time policy
/// still refuses a plain-HTTP origin outside the declared CIDRs
/// (`a_refused_destination_surfaces_as_egress_refused`).
#[test]
fn a_plain_http_origin_inside_the_declared_cidrs_loads() {
    std::env::set_var("EGR_C4B_TEN_USER", "ten-user");
    std::env::set_var("EGR_C4B_TEN_PASSWORD", "ten-pass");
    let config = runtime_config_with(
        vec![basic_binding(
            "private-api",
            "http://10.0.0.7:8080/",
            "EGR_C4B_TEN_USER",
            "EGR_C4B_TEN_PASSWORD",
        )],
        &["10.0.0.0/8"],
        None,
    );
    let endpoints = vec![pack_endpoint(
        "private-api",
        EndpointAuthentication::Basic {},
        &[],
    )];
    let egress = Egress::load(&endpoints, &config, &resolver())
        .expect("a plain-HTTP origin inside the declared CIDRs loads");
    assert!(egress.endpoint("private-api").is_some());
}

// Transport failures inside an admitted exchange.

/// An upstream that never accepts a connection: the failure is the
/// catchable `upstream.connection`, the certainty is not-sent, and the
/// failure carries neither a status nor a body.
#[tokio::test]
async fn an_unreachable_upstream_raises_connection_not_sent() {
    // A port with no listener by the time the send runs; the binding
    // pins its origin, so the send is admitted and dies at the connect.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
    let dead_port = probe.local_addr().expect("probe port").port();
    drop(probe);
    let (egress, credential) = {
        std::env::set_var("EGR_C4B_DEAD_USER", "dead-user");
        std::env::set_var("EGR_C4B_DEAD_PASSWORD", "dead-pass");
        let config = runtime_config(vec![basic_binding(
            "dead-api",
            &format!("http://127.0.0.1:{dead_port}/"),
            "EGR_C4B_DEAD_USER",
            "EGR_C4B_DEAD_PASSWORD",
        )]);
        let endpoints = vec![pack_endpoint(
            "dead-api",
            EndpointAuthentication::Basic {},
            &[],
        )];
        let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let credential = authorize(&egress, "dead-api", &mut budget, &mut events)
            .await
            .expect("a basic kind resolves its pair")
            .expect("a basic kind produces a header")
            .header;
        (egress, credential)
    };
    let bound = egress.endpoint("dead-api").expect("the endpoint");
    let error = bound
        .send(registry_adapter::egress::OutboundSend {
            link: &format!("http://127.0.0.1:{dead_port}/records"),
            exchange_headers: &[],
            shape: SendShape::Get,
            authorization: Some(&credential),
            attempt: ATTEMPT,
            maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            ok_status_ranges: OkStatusCodeRanges::default(),
            throw_exception_on_failure: true,
        })
        .await
        .expect_err("a dead upstream fails the send");
    let failure = upstream_failure(&error);
    assert_eq!(
        failure.class,
        ErrorClass::UpstreamConnection,
        "a connection that never establishes is the connection class"
    );
    assert_eq!(
        failure.certainty_journal_name(),
        "not-sent",
        "the destination never saw the request"
    );
    assert_eq!(failure.status, None);
    assert!(failure.body.is_none());
}

/// An upstream that accepts and then holds its silence past the
/// declared attempt: the failure is the catchable `upstream.timeout`
/// with the maybe-sent certainty, because the request went out and no
/// answer came back in time.
#[tokio::test]
async fn a_stalled_upstream_raises_timeout_maybe_sent() {
    // A listener that accepts and never answers.
    let stalled = std::net::TcpListener::bind("127.0.0.1:0").expect("stalled binds");
    let stalled_port = stalled.local_addr().expect("stalled port").port();
    let holder = std::thread::spawn(move || {
        // Hold each accepted connection open, reading nothing, until
        // the test ends and the listener drops.
        for stream in stalled.incoming() {
            let Ok(_stream) = stream else {
                continue;
            };
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    });
    let error = {
        // The binding pins the stalled listener's origin, so the send
        // is admitted, connects, and dies at the deadline.
        std::env::set_var("EGR_C4B_STALL_USER", "stall-user");
        std::env::set_var("EGR_C4B_STALL_PASSWORD", "stall-pass");
        let config = runtime_config(vec![basic_binding(
            "stall-api",
            &format!("http://127.0.0.1:{stalled_port}/"),
            "EGR_C4B_STALL_USER",
            "EGR_C4B_STALL_PASSWORD",
        )]);
        let endpoints = vec![pack_endpoint(
            "stall-api",
            EndpointAuthentication::Basic {},
            &[],
        )];
        let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let credential = authorize(&egress, "stall-api", &mut budget, &mut events)
            .await
            .expect("a basic kind resolves its pair")
            .expect("a basic kind produces a header")
            .header;
        let bound = egress.endpoint("stall-api").expect("the endpoint");
        bound
            .send(registry_adapter::egress::OutboundSend {
                link: &format!("http://127.0.0.1:{stalled_port}/records"),
                exchange_headers: &[],
                shape: SendShape::Get,
                authorization: Some(&credential),
                attempt: std::time::Duration::from_millis(800),
                maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
                ok_status_ranges: OkStatusCodeRanges::default(),
                throw_exception_on_failure: true,
            })
            .await
            .expect_err("a stalled upstream times out")
    };
    let failure = upstream_failure(&error);
    assert_eq!(
        failure.class,
        ErrorClass::UpstreamTimeout,
        "a deadline past an established connection is the timeout class"
    );
    assert_eq!(
        failure.certainty_journal_name(),
        "maybe-sent",
        "the request went out; only the answer was lost"
    );
    drop(holder);
}

/// A response head over the platform bound is `upstream.too-large`,
/// maybe-sent: the reply arrived and was refused at the head, never
/// decoded.
#[tokio::test]
async fn an_over_bound_response_head_raises_too_large() {
    let upstream = UpstreamDouble::start();
    // One Content-Type value far over the platform's 64 KiB head
    // bound; leaked so the double's script holds it for the test.
    let oversized_media_type: &'static str = Box::leak("a".repeat(100_000).into_boxed_str());
    upstream.respond_with(vec![upstream::Response {
        status: 200,
        media_type: oversized_media_type,
        body: String::new(),
    }]);
    let (egress, credential) = load_basic_and_authorize(
        &upstream,
        "large-api",
        "EGR_C4B_LARGE_USER",
        "EGR_C4B_LARGE_PASSWORD",
        "large-user",
        "large-pass",
    )
    .await;
    let bound = egress.endpoint("large-api").expect("the endpoint");
    let error = bound
        .send(outbound(
            &upstream.url("/records"),
            &credential,
            ATTEMPT,
            true,
        ))
        .await
        .expect_err("an over-bound head is a failure");
    let failure = upstream_failure(&error);
    assert_eq!(
        failure.class,
        ErrorClass::UpstreamTooLarge,
        "an over-bound head is the too-large class"
    );
    assert_eq!(
        failure.certainty_journal_name(),
        "maybe-sent",
        "the reply arrived; only its head was unusable"
    );
    assert!(
        failure.body.is_none(),
        "an over-bound head never decodes a body"
    );
}

/// The send's own Debug rendering is value-free: a marker riding the
/// exchange header value, the request body, or the credential value
/// appears nowhere in it, because a caller's diagnostic render is the
/// one place a credential could leak without ever reaching the wire.
#[test]
fn a_send_debug_render_carries_no_value() {
    const MARKER: &str = "c4b-outbound-marker-77b1c9";
    let credential = registry_adapter::auth::AuthHeader::new(
        "authorization",
        registry_adapter::auth::ProtectedText::from_str_value(&format!(
            "Bearer token-{MARKER}-credential"
        )),
    );
    let exchange_headers = [("x-trace".to_owned(), format!("trace-{MARKER}-header"))];
    let body_bytes = format!(r#"{{"record": "{MARKER}-body"}}"#).into_bytes();
    let send = registry_adapter::egress::OutboundSend {
        link: "http://127.0.0.1:1/records",
        exchange_headers: &exchange_headers,
        shape: SendShape::Post(SendBody {
            format: SendBodyFormat::Json,
            bytes: &body_bytes,
        }),
        authorization: Some(&credential),
        attempt: ATTEMPT,
        maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
        ok_status_ranges: OkStatusCodeRanges::default(),
        throw_exception_on_failure: true,
    };
    let rendered = format!("{send:?}");
    assert!(
        !rendered.contains(MARKER),
        "the Debug render never carries a marker: {rendered}"
    );
    assert!(
        rendered.contains("x-trace"),
        "header names stay visible: {rendered}"
    );
}

// Outbound TLS material.

/// Throwaway self-signed fixture generated for these tests only; no
/// deployment has ever trusted it. The same root the auth TLS unit
/// parses.
const TEST_ROOT_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBnzCCAUWgAwIBAgIUGSkZVSD93tTafMYk9zXkW+9N+VcwCgYIKoZIzj0EAwIw\nJTEjMCEGA1UEAwwaUmVnaXN0cnkgQWRhcHRlciBUZXN0IFJvb3QwHhcNMjYxMDMw\nMDQ1NDIwWhcNMzYxMDI3MDQ1NDIwWjAlMSMwIQYDVQQDDBpSZWdpc3RyeSBBZGFw\ndGVyIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIDV7zIjqChx\n97aw2DaQUGi02tuThFuNl5IKP4RFr+5lxRclqsvlNfhU0Y4JnNLDuxdToqXgVKz6\nDnA2hpkMqZyjUzBRMB0GA1UdDgQWBBSPV2C1/cYwPYf/YYcSqJMvbWT8OjAfBgNV\nHSMEGDAWgBSPV2C1/cYwPYf/YYcSqJMvbWT8OjAPBgNVHRMBAf8EBTADAQH/MAoG\nCCqGSM49BAMCA0gAMEUCIQDE6ceiEQLBfR3wcAbPoXkClwMWZCs+QRHpi9asKR6w\nGwIgG/WsmuvsVVNeDynYVj92+B5SNtyVRK2+p3eo97VtmF0=\n-----END CERTIFICATE-----\n";

/// Write one bundle file under a unique temp path and return it; the
/// caller removes it.
fn bundle_file(name: &str, contents: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("registry-adapter-egress-tls-{name}-{unique}.pem"));
    std::fs::write(&path, contents).expect("write bundle");
    path
}

/// A declared trust profile whose bundle parses installs at load on an
/// HTTPS binding; the endpoint's send policy holds the configured CA
/// from startup, fail-closed. The right-CA and wrong-CA handshake
/// cases over a real TLS exchange live in tests/egress_tls_wiring.rs,
/// under the postgres-test feature and its loopback HTTPS double.
#[test]
fn a_declared_ca_bundle_parses_and_installs_at_load() {
    std::env::set_var("EGR_C4B_TLS_USER", "tls-user");
    std::env::set_var("EGR_C4B_TLS_PASSWORD", "tls-pass");
    let path = bundle_file("root", TEST_ROOT_CERTIFICATE_PEM);
    let tls = registry_adapter_core::OutboundTls {
        trust_profiles: std::collections::BTreeMap::from([(
            "private-ca".to_owned(),
            registry_adapter_core::TrustProfile {
                ca_bundle_file: path.to_string_lossy().into_owned(),
            },
        )]),
    };
    let mut binding = basic_binding(
        "tls-api",
        "https://127.0.0.1:1/",
        "EGR_C4B_TLS_USER",
        "EGR_C4B_TLS_PASSWORD",
    );
    binding.tls_trust_profile = Some(LocalId::new("private-ca").expect("profile id"));
    let config = runtime_config_with(vec![binding], &["192.168.0.0/16"], Some(tls));
    let endpoints = vec![pack_endpoint(
        "tls-api",
        EndpointAuthentication::Basic {},
        &[],
    )];
    let egress =
        Egress::load(&endpoints, &config, &resolver()).expect("a parsing bundle installs at load");
    assert!(egress.endpoint("tls-api").is_some());
    std::fs::remove_file(&path).expect("remove bundle");
}

/// An unusable bundle refuses the whole load, and the refusal renders
/// value-free: it names neither the profile, the path, nor the file's
/// content.
#[test]
fn an_unusable_ca_bundle_refuses_the_load_value_free() {
    std::env::set_var("EGR_C4B_BADTLS_USER", "bad-tls-user");
    std::env::set_var("EGR_C4B_BADTLS_PASSWORD", "bad-tls-pass");
    let path = bundle_file("garbage", "not a certificate at all");
    let tls = registry_adapter_core::OutboundTls {
        trust_profiles: std::collections::BTreeMap::from([(
            "private-ca".to_owned(),
            registry_adapter_core::TrustProfile {
                ca_bundle_file: path.to_string_lossy().into_owned(),
            },
        )]),
    };
    let mut binding = basic_binding(
        "tls-api",
        "https://127.0.0.1:1/",
        "EGR_C4B_BADTLS_USER",
        "EGR_C4B_BADTLS_PASSWORD",
    );
    binding.tls_trust_profile = Some(LocalId::new("private-ca").expect("profile id"));
    let config = runtime_config_with(vec![binding], &["192.168.0.0/16"], Some(tls));
    let endpoints = vec![pack_endpoint(
        "tls-api",
        EndpointAuthentication::Basic {},
        &[],
    )];
    let error = match Egress::load(&endpoints, &config, &resolver()) {
        Err(fault) => fault,
        Ok(_) => panic!("an unusable bundle refuses the load"),
    };
    let rendered = error.to_string();
    assert!(
        !rendered.contains("private-ca") && !rendered.contains("registry-adapter-egress-tls"),
        "the refusal is value-free: {rendered}"
    );
    std::fs::remove_file(&path).expect("remove bundle");
}

/// One basic endpoint declared at `attempt` milliseconds and `bytes`
/// response bytes, bound at the given optional lower limits.
fn limited_deployment(
    declared: (u64, u64),
    bound: (Option<u64>, Option<u64>),
) -> Result<Egress, EgressFault> {
    std::env::set_var("EGR_LIMITS_USER", "limits-user");
    std::env::set_var("EGR_LIMITS_PASSWORD", "limits-password");
    let mut binding = basic_binding(
        "limits-api",
        "http://127.0.0.1:9/",
        "EGR_LIMITS_USER",
        "EGR_LIMITS_PASSWORD",
    );
    binding.attempt_timeout_milliseconds = bound
        .0
        .map(|value| BoundedU64::new(value).expect("bound attempt"));
    binding.maximum_response_bytes = bound
        .1
        .map(|value| BoundedU64::new(value).expect("bound bytes"));
    let mut endpoint = pack_endpoint("limits-api", EndpointAuthentication::Basic {}, &[]);
    endpoint.attempt_timeout_milliseconds = BoundedU64::new(declared.0).expect("declared attempt");
    endpoint.maximum_response_bytes = BoundedU64::new(declared.1).expect("declared bytes");
    Egress::load(&[endpoint], &runtime_config(vec![binding]), &resolver())
}

/// The pack's declared limits are the endpoint's effective limits, and a
/// binding may lower either.
#[test]
fn the_declared_limits_apply_and_a_binding_may_lower_them() {
    let declared = limited_deployment((5_000, 65_536), (None, None)).expect("loads");
    let bound = declared.endpoint("limits-api").expect("endpoint");
    assert_eq!(bound.attempt(), std::time::Duration::from_millis(5_000));
    assert_eq!(bound.maximum_response_bytes(), 65_536);

    let lowered = limited_deployment((5_000, 65_536), (Some(2_000), Some(4_096))).expect("loads");
    let bound = lowered.endpoint("limits-api").expect("endpoint");
    assert_eq!(bound.attempt(), std::time::Duration::from_millis(2_000));
    assert_eq!(bound.maximum_response_bytes(), 4_096);
}

/// A binding that raises either limit above the declared one is refused at
/// load, never shortened.
#[test]
fn a_binding_above_the_declared_limit_is_refused_at_load() {
    for bound in [(Some(5_001), None), (None, Some(65_537))] {
        let error = limited_deployment((5_000, 65_536), bound)
            .err()
            .expect("the load refuses");
        assert!(
            matches!(error, EgressFault::LimitAboveDeclared { .. }),
            "{error}"
        );
    }
}
