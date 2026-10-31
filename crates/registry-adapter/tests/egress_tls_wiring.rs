// SPDX-License-Identifier: Apache-2.0

//! The endpoint's frozen destinations over a real TLS exchange: an
//! HTTPS binding whose origin and token endpoint are one locally
//! terminated loopback certificate acquires its bearer credential and
//! sends its data through the same configured CA bundle, fail-closed,
//! and a deployment trusting a different CA never completes a
//! handshake on either path (`products/adapter/CONCEPT.md` section
//! 10.2).
//!
//! This suite needs the platform's pinned-loopback HTTPS test profile,
//! which only the postgres-test feature enables; a plain cargo test run
//! compiles none of it, and products/adapter/scripts/test-postgres.sh
//! runs it with the feature set.

#![cfg(feature = "postgres-test")]

use registry_adapter::engine::auth::{
    AuthError, ClientAssertion, ClientAssertionSigner, ProtectedText, TokenBudget,
};
use registry_adapter::engine::egress::{Egress, EgressError, OkStatusCodeRanges, SendShape};
use registry_adapter_core::{
    AnonymousHttpsAcknowledgement, ComponentKind, CredentialPlacement, Endpoint,
    EndpointAuthentication, EndpointBinding, ErrorClass, RuntimeCredential,
};
use registry_platform_config::SecretResolver;
use registry_platform_yaml::{
    BoundedU64, ExternalId, LocalId, SecretProvider, SecretReference, UniqueList, Url,
};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use rcgen::CertifiedKey;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;

/// The PEM encoding of one DER certificate, the form a CA bundle
/// carries; rcgen's own PEM writer sits behind a feature this suite
/// does not take.
fn pem_certificate(der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let encoded = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is text"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

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

/// One recorded request: the target, its headers, and its body.
type RecordedRequest = (String, Vec<(String, String)>, Vec<u8>);

/// One loopback HTTPS double: a locally terminated rcgen certificate,
/// one request per connection, a scripted response queue, and a
/// value-complete record of every request it received.
struct TlsDouble {
    address: SocketAddr,
    certificate_pem: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    responses: Arc<Mutex<std::collections::VecDeque<(u16, String, String)>>>,
}

impl TlsDouble {
    /// Start the double on an unused loopback port, its certificate
    /// carrying the `127.0.0.1` IP SAN.
    async fn start() -> Self {
        let CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
                .expect("generate the test certificate");
        let certificate_der = cert.der().clone();
        let certificate_pem = pem_certificate(cert.der().as_ref());
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key)
            .expect("build the test TLS configuration");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the TLS double");
        let address = listener.local_addr().expect("the TLS double's address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let serve_requests = Arc::clone(&requests);
        let serve_responses = Arc::clone(&responses);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let acceptor = acceptor.clone();
                let requests = Arc::clone(&serve_requests);
                let responses = Arc::clone(&serve_responses);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Ok(Some(request)) = read_tls_request(&mut stream).await else {
                        return;
                    };
                    requests
                        .lock()
                        .expect("the TLS double's request record")
                        .push(request);
                    let response = responses
                        .lock()
                        .expect("the TLS double's response script")
                        .pop_front()
                        .unwrap_or_else(|| {
                            (
                                500,
                                "text/plain".to_owned(),
                                "the response script is exhausted".to_owned(),
                            )
                        });
                    let (status, media_type, body) = response;
                    let head = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Type: {media_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(body.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            address,
            certificate_pem,
            requests,
            responses,
        }
    }

    /// The https origin URL for one path.
    fn url(&self, path: &str) -> String {
        format!("https://{address}{path}", address = self.address)
    }

    /// Script the responses, served in order, one per request.
    fn respond_with(&self, responses: Vec<(u16, &str, &str)>) {
        *self.responses.lock().expect("the response script") = responses
            .into_iter()
            .map(|(status, media_type, body)| (status, media_type.to_owned(), body.to_owned()))
            .collect();
    }

    /// Every request the double received: target, headers, body.
    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("the request record").clone()
    }

    /// How many requests the double received.
    fn request_count(&self) -> usize {
        self.requests.lock().expect("the request record").len()
    }
}

/// Read one HTTP/1.1 request over the TLS stream: head, then
/// `content-length` body bytes. Returns `None` when the client went
/// away before a full head arrived, the handshake-failure shape.
async fn read_tls_request(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
) -> std::io::Result<Option<RecordedRequest>> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 512];
    let head_end = loop {
        if let Some(position) = find_head_end(&buffer) {
            break position;
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > 64 * 1024 {
            return Ok(None);
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let _method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let content_length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(Some((target, headers, body)))
}

/// The offset of the first end-of-head marker.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn header<'a>(request: &'a RecordedRequest, name: &str) -> Option<&'a str> {
    request
        .1
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The runtime config for one binding with the private-ca trust
/// profile pointing at the given bundle file.
fn tls_config(
    binding: EndpointBinding,
    bundle_path: &std::path::Path,
) -> registry_adapter_core::AdapterEndpointBindings {
    registry_adapter_core::AdapterEndpointBindings {
        id: LocalId::new("tls-deployment").expect("deployment id"),
        endpoints: registry_platform_yaml::UniqueIdList::new(vec![binding]).expect("bindings"),
        allowed_private_cidrs: UniqueList::new(Vec::new()).expect("cidrs"),
        outbound_tls: Some(registry_adapter_core::OutboundTls {
            trust_profiles: BTreeMap::from([(
                "private-ca".to_owned(),
                registry_adapter_core::TrustProfile {
                    ca_bundle_file: bundle_path.to_string_lossy().into_owned(),
                },
            )]),
        }),
    }
}

fn pack_endpoint(id: &str, authentication: EndpointAuthentication) -> Endpoint {
    Endpoint {
        id: LocalId::new(id).expect("endpoint id"),
        component: ComponentKind::Http,
        authentication,
        attempt_timeout_milliseconds: registry_platform_yaml::BoundedU64::new(10_000)
            .expect("attempt timeout"),
        maximum_response_bytes: registry_platform_yaml::BoundedU64::new(1_048_576)
            .expect("response bound"),
        response_headers: UniqueList::new(Vec::new()).expect("response headers"),
        request_headers: UniqueList::new(Vec::new()).expect("request headers"),
        operations: Vec::new(),
        tested_versions: Vec::new(),
        query_file: None,
        operation_name: None,
        variables: None,
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
        anonymous_https: None,
        tls_trust_profile: Some(LocalId::new("private-ca").expect("profile id")),
        mtls_identity: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
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
        anonymous_https: None,
        tls_trust_profile: Some(LocalId::new("private-ca").expect("profile id")),
        mtls_identity: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
    }
}

fn anonymous_binding(endpoint: &str, base_url: &str) -> EndpointBinding {
    EndpointBinding {
        endpoint: ExternalId::new(endpoint).expect("endpoint id"),
        base_url: Url::new(base_url).expect("base url"),
        credential: Some(RuntimeCredential::None {}),
        anonymous_https: Some(AnonymousHttpsAcknowledgement::OperatorApproved),
        tls_trust_profile: Some(LocalId::new("private-ca").expect("profile id")),
        mtls_identity: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
    }
}

/// Write one bundle file under a unique temp path; the caller removes
/// it.
fn bundle_file(name: &str, contents: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "registry-adapter-egress-tls-wiring-{name}-{unique}.pem"
    ));
    std::fs::write(&path, contents).expect("write bundle");
    path
}

const ATTEMPT: std::time::Duration = std::time::Duration::from_secs(10);
const MAXIMUM_RESPONSE_BYTES: usize = 64 * 1024;

/// An acknowledged anonymous source still uses the normal frozen TLS
/// transport, but authorization resolves no credential and the send carries
/// neither source-authentication nor caller-token headers.
#[tokio::test]
async fn acknowledged_anonymous_https_sends_no_authentication_header() {
    let upstream = TlsDouble::start().await;
    upstream.respond_with(vec![(200, "application/json", r#"{"tls":true}"#)]);
    let bundle = bundle_file("anonymous", &upstream.certificate_pem);
    let config = tls_config(anonymous_binding("tls-api", &upstream.url("/")), &bundle);
    let endpoints = vec![pack_endpoint("tls-api", EndpointAuthentication::None {})];
    let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");
    let bound = egress.endpoint("tls-api").expect("the endpoint");

    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let credential = bound
        .authorize(&mut budget, &resolver(), &TestSigner, &mut events)
        .await
        .expect("none authorization succeeds");
    assert!(credential.is_none());
    bound
        .send(registry_adapter::egress::OutboundSend {
            link: &upstream.url("/records"),
            exchange_headers: &[],
            shape: SendShape::Get,
            authorization: None,
            attempt: ATTEMPT,
            maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            ok_status_ranges: OkStatusCodeRanges::default(),
            throw_exception_on_failure: true,
        })
        .await
        .expect("the anonymous HTTPS send succeeds");

    let requests = upstream.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(header(&requests[0], "authorization"), None);
    assert_eq!(header(&requests[0], "proxy-authorization"), None);
    assert_eq!(header(&requests[0], "cookie"), None);
    std::fs::remove_file(&bundle).expect("remove bundle");
}

/// The right CA completes both halves over real TLS: the token
/// acquisition runs through the frozen transport against the locally
/// terminated certificate, and the data send rides the issued
/// credential through the same trust, so the configured bundle is the
/// only trust either destination takes.
#[tokio::test]
async fn the_right_ca_completes_the_token_and_data_sends_over_tls() {
    std::env::set_var("TLS_C4B_GOOD_ID", "tls-client");
    std::env::set_var("TLS_C4B_GOOD_SECRET", "tls-secret");
    let upstream = TlsDouble::start().await;
    upstream.respond_with(vec![
        (
            200,
            "application/json",
            r#"{"access_token":"tls-token-1","token_type":"Bearer","expires_in":3600}"#,
        ),
        (200, "application/json", r#"{"tls":true}"#),
    ]);
    let bundle = bundle_file("right", &upstream.certificate_pem);
    let config = tls_config(
        oauth_binding(
            "tls-api",
            &upstream.url("/"),
            &upstream.url("/token"),
            "TLS_C4B_GOOD_ID",
            "TLS_C4B_GOOD_SECRET",
        ),
        &bundle,
    );
    let endpoints = vec![pack_endpoint(
        "tls-api",
        EndpointAuthentication::Oauth2ClientCredentials {},
    )];
    let egress = Egress::load(&endpoints, &config, &resolver()).expect("the deployment loads");
    let bound = egress.endpoint("tls-api").expect("the endpoint");

    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let credential = bound
        .authorize(&mut budget, &resolver(), &TestSigner, &mut events)
        .await
        .expect("the token acquisition completes over TLS");
    let credential = credential.expect("an oauth2 kind produces a header").header;

    let reply = bound
        .send(registry_adapter::engine::egress::OutboundSend {
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
        .expect("the data send completes over TLS");
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, serde_json::json!({ "tls": true }));

    let requests = upstream.requests();
    assert_eq!(requests.len(), 2, "token, then data");
    assert_eq!(requests[0].0, "/token");
    assert_eq!(
        header(&requests[0], "authorization"),
        // base64("tls-client:tls-secret")
        Some("Basic dGxzLWNsaWVudDp0bHMtc2VjcmV0"),
        "the Basic pair rides the token request over TLS"
    );
    assert_eq!(requests[1].0, "/records");
    assert_eq!(
        header(&requests[1], "authorization"),
        Some("Bearer tls-token-1"),
        "the issued credential rides the data send over TLS"
    );
    std::fs::remove_file(&bundle).expect("remove bundle");
}

/// A deployment trusting a different CA never completes a handshake on
/// either path: the data send fails as the catchable `upstream.connection`
/// with the not-sent certainty, the token acquisition fails as the
/// transport's connect kind, and no request reaches the double, so a
/// credential can never leave over a trust the deployment did not pin.
#[tokio::test]
async fn the_wrong_ca_completes_neither_handshake() {
    std::env::set_var("TLS_C4B_BADTLS_USER", "bad-tls-user");
    std::env::set_var("TLS_C4B_BADTLS_PASSWORD", "bad-tls-pass");
    std::env::set_var("TLS_C4B_BAD_ID", "bad-tls-client");
    std::env::set_var("TLS_C4B_BAD_SECRET", "bad-tls-secret");
    let upstream = TlsDouble::start().await;
    upstream.respond_with(vec![(200, "application/json", r#"{"never":true}"#)]);
    // A second, unrelated self-signed certificate: what this
    // deployment trusts, and what the double never presents.
    let unrelated = rcgen::generate_simple_self_signed(vec!["other.example.invalid".to_owned()])
        .expect("generate the unrelated certificate");
    let bundle = bundle_file("wrong", &pem_certificate(unrelated.cert.der().as_ref()));

    // The data path: the send fails inside the handshake, before any
    // byte of the request is trusted.
    let config = tls_config(
        basic_binding(
            "tls-api",
            &upstream.url("/"),
            "TLS_C4B_BADTLS_USER",
            "TLS_C4B_BADTLS_PASSWORD",
        ),
        &bundle,
    );
    let endpoints = vec![pack_endpoint("tls-api", EndpointAuthentication::Basic {})];
    let egress = Egress::load(&endpoints, &config, &resolver())
        .expect("the binding loads; the trust mismatch refuses at send time");
    let bound = egress.endpoint("tls-api").expect("the endpoint");
    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let credential = bound
        .authorize(&mut budget, &resolver(), &TestSigner, &mut events)
        .await
        .expect("a basic kind resolves its pair");
    let credential = credential.expect("a basic kind produces a header").header;
    let error = bound
        .send(registry_adapter::engine::egress::OutboundSend {
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
        .expect_err("the handshake fails under the wrong CA");
    match &error {
        EgressError::Upstream(failure) => {
            assert_eq!(
                failure.class,
                ErrorClass::UpstreamConnection,
                "a failed handshake is the connection class"
            );
            assert_eq!(
                failure.certainty_journal_name(),
                "not-sent",
                "the request was never trusted out"
            );
        }
        EgressError::Refused(refusal) => {
            panic!("a handshake failure is not a refusal: {refusal:?}")
        }
    }

    // The token path: the same mismatch refuses the acquisition as the
    // transport's connect kind, never a policy refusal and never a
    // credential judgment.
    let config = tls_config(
        oauth_binding(
            "tls-oauth-api",
            &upstream.url("/"),
            &upstream.url("/token"),
            "TLS_C4B_BAD_ID",
            "TLS_C4B_BAD_SECRET",
        ),
        &bundle,
    );
    let endpoints = vec![pack_endpoint(
        "tls-oauth-api",
        EndpointAuthentication::Oauth2ClientCredentials {},
    )];
    let egress = Egress::load(&endpoints, &config, &resolver())
        .expect("the binding loads; the trust mismatch refuses at acquisition time");
    let bound = egress.endpoint("tls-oauth-api").expect("the endpoint");
    let mut budget = TokenBudget::new_exchange();
    let mut events = Vec::new();
    let error = bound
        .authorize(&mut budget, &resolver(), &TestSigner, &mut events)
        .await
        .expect_err("the acquisition fails inside the handshake");
    match &error {
        AuthError::Token(registry_adapter::engine::auth::TokenFault::Transport { kind }) => {
            assert_eq!(
                kind.kind(),
                "connect",
                "a failed handshake is the transport's connect kind: {error}"
            );
            assert_eq!(
                error.class(),
                "upstream.connection",
                "the class agrees with the data path"
            );
        }
        other => panic!("a handshake failure is a transport connect: {other:?}"),
    }
    assert_eq!(
        upstream.request_count(),
        0,
        "neither handshake ever reached the double"
    );
    std::fs::remove_file(&bundle).expect("remove bundle");
}
