// SPDX-License-Identifier: Apache-2.0

//! The deployment's outbound egress state, exercised over a real
//! loopback HTTP double: one compiled auth plan per endpoint binding is
//! held from startup, a data send carries the exchange's selected
//! headers with the credential injected after them, and the whole
//! deployment refuses to start when an endpoint's kind needs the token
//! send this build does not wire yet, so the gap is visible at startup
//! and never at a first request (`products/adapter/CONCEPT.md`
//! sections 8.11 and 10.2).

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

use registry_adapter::auth::{
    AuthError, AuthEvent, AuthPlanFault, ClientAssertion, ClientAssertionSigner, ProtectedText,
    TokenBudget,
};
use registry_adapter::egress::{
    Egress, EgressError, EgressFault, EgressRefusal, SendBody, SendBodyFormat, SendShape,
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
        ok_status_range: (200, 299),
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

/// An endpoint whose kind acquires a token refuses the whole
/// deployment's load while the token send is not wired: the gap is
/// visible at startup with a named refusal, never at a first request
/// and never silently.
#[test]
fn an_oauth2_kind_refuses_the_load_until_the_token_send_is_wired() {
    std::env::set_var("EGR_C4B_WIRE_ID", "wire-client");
    std::env::set_var("EGR_C4B_WIRE_SECRET", "wire-secret");
    let config = runtime_config(vec![oauth_binding(
        "cases-api",
        "http://127.0.0.1:1/",
        "https://token.example.invalid/token",
        "EGR_C4B_WIRE_ID",
        "EGR_C4B_WIRE_SECRET",
    )]);
    let endpoints = vec![pack_endpoint(
        "cases-api",
        EndpointAuthentication::Oauth2ClientCredentials {},
        &[],
    )];
    let error = match Egress::load(&endpoints, &config, &resolver()) {
        Err(fault) => fault,
        Ok(_) => panic!("an unwired token send refuses the load"),
    };
    assert!(
        matches!(error, EgressFault::TokenSendUnwired),
        "the load refuses with the named unwired fault: {error:?}"
    );
    let rendered = error.to_string();
    assert!(
        !rendered.contains("wire-secret") && !rendered.contains("wire-client"),
        "the refusal never carries credential material: {rendered}"
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
            ok_status_range: (200, 299),
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
            ok_status_range: (200, 299),
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
            ok_status_range: (200, 299),
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

/// A redirect is never followed: the 3xx answer raises
/// `upstream.redirect` and the double sees exactly one request.
#[tokio::test]
async fn a_redirect_is_raised_and_never_followed() {
    std::env::set_var("EGR_C4B_REDIR_USER", "redirect-user");
    std::env::set_var("EGR_C4B_REDIR_PASSWORD", "redirect-pass");
    let upstream = UpstreamDouble::start();
    upstream.respond_with(vec![upstream::Response {
        status: 302,
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
            ok_status_range: (200, 299),
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
    assert_eq!(failure.status, Some(302));
    assert_eq!(
        upstream.request_count(),
        1,
        "the redirect's Location is never requested"
    );
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
            ok_status_range: (200, 299),
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
            ok_status_range: (200, 299),
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
            ok_status_range: (200, 299),
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

/// Out of range and undecodable under the throw flag: the send answers
/// `upstream.http` with no decoded body, because the route is ending
/// anyway and the body never decoded.
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
/// detail, and its status (CONCEPT 8.11).
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
/// (CONCEPT 8.11's `throwExceptionOnFailure: false`).
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
/// from startup, fail-closed. The wrong-CA handshake case needs the
/// platform's loopback HTTPS double and stays deferred with FLAG 2's
/// ruling (no new dev-dependency; Cargo.lock does not move).
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
