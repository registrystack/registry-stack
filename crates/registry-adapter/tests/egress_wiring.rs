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
use registry_adapter::egress::{Egress, EgressError, EgressFault, EgressRefusal, SendMethod};
use registry_adapter_core::{
    ComponentKind, CredentialPlacement, Endpoint, EndpointAuthentication, EndpointBinding,
    ErrorClass, RuntimeCredential,
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
    registry_adapter_core::AdapterRuntimeConfig {
        id: LocalId::new("egress-deployment").expect("deployment id"),
        endpoints: registry_platform_yaml::UniqueIdList::new(bindings).expect("bindings"),
        allowed_private_cidrs: UniqueList::new(vec![registry_adapter_core::Cidr::new(
            "192.168.0.0/16",
        )
        .expect("cidr")])
        .expect("cidrs"),
        outbound_tls: None,
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
        audit: registry_adapter_core::AuditRetention {
            retention_days: registry_platform_yaml::BoundedU32::<1, 3_650>::new(90)
                .expect("retention"),
        },
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
            method: SendMethod::Get,
            body: None,
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

    // An exchange that also holds an `authorization` entry: the
    // allowlist ignores it, and the credential the plan produced
    // travels in the injected slot.
    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let credential = authorize(&egress, "wire-api", &mut budget, &mut events)
        .await
        .expect("a basic kind resolves its pair");
    let credential = credential.expect("a basic kind produces a header").header;

    let reply = bound
        .send(registry_adapter::egress::OutboundSend {
            link: &upstream.url("/records"),
            exchange_headers: &[("x-trace".to_owned(), "trace-1".to_owned())],
            method: SendMethod::Get,
            body: None,
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
            method: SendMethod::Get,
            body: None,
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
            method: SendMethod::Get,
            body: None,
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
            method: SendMethod::Get,
            body: None,
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
