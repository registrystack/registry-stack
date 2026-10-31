// SPDX-License-Identifier: Apache-2.0

//! Synthetic HTTP and mutual-TLS upstreams for the source-shape fixtures.
//! Both terminate a real socket and preserve the complete request transcript.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

#[path = "../upstream/mod.rs"]
#[allow(dead_code)]
mod plain;

/// One request received by either transport.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// One scripted answer.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

/// The transport an experiment declares.
pub enum Upstream {
    Plain(plain::UpstreamDouble),
    MutualTls(MutualTlsDouble),
}

impl Upstream {
    pub fn plain() -> Self {
        Self::Plain(plain::UpstreamDouble::start())
    }

    pub async fn mutual_tls() -> Self {
        Self::MutualTls(MutualTlsDouble::start().await)
    }

    pub fn url(&self, path: &str) -> String {
        match self {
            Self::Plain(double) => double.url(path),
            Self::MutualTls(double) => double.url(path),
        }
    }

    pub fn respond_with(&self, responses: Vec<Response>) {
        match self {
            Self::Plain(double) => double.respond_with(
                responses
                    .into_iter()
                    .map(|response| plain::Response::json(response.status, &response.body))
                    .collect(),
            ),
            Self::MutualTls(double) => double.respond_with(responses),
        }
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        match self {
            Self::Plain(double) => double
                .requests()
                .into_iter()
                .map(|request| RecordedRequest {
                    method: request.method,
                    target: request.target,
                    headers: request.headers,
                    body: request.body,
                })
                .collect(),
            Self::MutualTls(double) => double.requests(),
        }
    }

    pub fn ca_bundle_path(&self) -> Option<&std::path::Path> {
        match self {
            Self::Plain(_) => None,
            Self::MutualTls(double) => Some(&double.ca_bundle_path),
        }
    }

    pub fn client_certificate_pem(&self) -> Option<&str> {
        match self {
            Self::Plain(_) => None,
            Self::MutualTls(double) => Some(&double.client_certificate_pem),
        }
    }

    pub fn client_key_pem(&self) -> Option<&str> {
        match self {
            Self::Plain(_) => None,
            Self::MutualTls(double) => Some(&double.client_key_pem),
        }
    }

    pub fn handshake_errors(&self) -> Vec<String> {
        match self {
            Self::Plain(_) => Vec::new(),
            Self::MutualTls(double) => double.handshake_errors(),
        }
    }
}

/// A real TLS server that requires a client certificate signed by its
/// private test CA. Successful HTTP receipt therefore proves mTLS, not merely
/// server-authenticated HTTPS.
pub struct MutualTlsDouble {
    address: std::net::SocketAddr,
    ca_bundle_path: std::path::PathBuf,
    client_certificate_pem: String,
    client_key_pem: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    responses: Arc<Mutex<VecDeque<Response>>>,
    handshake_errors: Arc<Mutex<Vec<String>>>,
    _directory: tempfile::TempDir,
}

impl MutualTlsDouble {
    async fn start() -> Self {
        let mut ca_params = CertificateParams::new(Vec::new()).expect("empty CA SAN list");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Adapter experiment CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().expect("generate the test CA key");
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("sign the test CA");

        let mut server_params =
            CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("server SAN");
        server_params
            .distinguished_name
            .push(DnType::CommonName, "Adapter experiment upstream");
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().expect("generate the server key");
        let server_certificate = server_params
            .signed_by(&server_key, &ca)
            .expect("sign the server certificate");

        let mut client_params =
            CertificateParams::new(vec!["adapter-experiment-client".to_owned()])
                .expect("client SAN");
        client_params
            .distinguished_name
            .push(DnType::CommonName, "Adapter experiment client");
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().expect("generate the client key");
        let client_certificate = client_params
            .signed_by(&client_key, &ca)
            .expect("sign the client certificate");

        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(ca.der().clone())
            .expect("trust the client CA");
        let client_verifier =
            tokio_rustls::rustls::server::WebPkiClientVerifier::builder(client_roots.into())
                .build()
                .expect("build the mandatory client verifier");
        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![server_certificate.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("build the mutual-TLS server");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the mutual-TLS double");
        let address = listener.local_addr().expect("mutual-TLS address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(VecDeque::new()));
        let served_requests = Arc::clone(&requests);
        let served_responses = Arc::clone(&responses);
        let handshake_errors = Arc::new(Mutex::new(Vec::new()));
        let served_handshake_errors = Arc::clone(&handshake_errors);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let acceptor = acceptor.clone();
                let requests = Arc::clone(&served_requests);
                let responses = Arc::clone(&served_responses);
                let handshake_errors = Arc::clone(&served_handshake_errors);
                tokio::spawn(async move {
                    let mut stream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            handshake_errors
                                .lock()
                                .expect("handshake error record")
                                .push(error.to_string());
                            return;
                        }
                    };
                    let Ok(Some(request)) = read_request(&mut stream).await else {
                        return;
                    };
                    requests.lock().expect("request transcript").push(request);
                    let response = responses
                        .lock()
                        .expect("response script")
                        .pop_front()
                        .unwrap_or(Response {
                            status: 500,
                            body: "the response script is exhausted".to_owned(),
                        });
                    let head = format!(
                        "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response.status,
                        response.body.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(response.body.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        let directory = tempfile::tempdir().expect("mutual-TLS scratch directory");
        let ca_bundle_path = directory.path().join("ca.pem");
        std::fs::write(&ca_bundle_path, pem("CERTIFICATE", ca.der().as_ref()))
            .expect("write the CA bundle");
        Self {
            address,
            ca_bundle_path,
            client_certificate_pem: pem("CERTIFICATE", client_certificate.der().as_ref()),
            client_key_pem: pem("PRIVATE KEY", &client_key.serialize_der()),
            requests,
            responses,
            handshake_errors,
            _directory: directory,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.address)
    }

    fn respond_with(&self, responses: Vec<Response>) {
        *self.responses.lock().expect("response script") = responses.into();
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("request transcript").clone()
    }

    fn handshake_errors(&self) -> Vec<String> {
        self.handshake_errors
            .lock()
            .expect("handshake error record")
            .clone()
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut output = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(chunk).expect("base64 is UTF-8"));
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    output
}

async fn read_request(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
) -> std::io::Result<Option<RecordedRequest>> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let head_end = loop {
        if let Some(position) = buffer.windows(4).position(|part| part == b"\r\n\r\n") {
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
    let head = String::from_utf8_lossy(&buffer[..head_end]);
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_owned();
    let target = request_line.next().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or_default();
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Ok(Some(RecordedRequest {
        method,
        target,
        headers,
        body,
    }))
}
